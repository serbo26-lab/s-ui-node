package connectionpolicy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing-box/transport/v2raygrpc"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/sagernet/sing/service"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// NewServerTransport reuses the transport's HTTP implementation. Its own
// listener binds a physical peer before forwarded routing headers are parsed.
func NewServerTransport(ctx context.Context, logger logger.ContextLogger, options option.V2RayTransportOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (adapter.V2RayServerTransport, error) {
	if service.FromContext[Guard](ctx) == nil {
		return v2ray.NewServerTransport(ctx, logger, options, tlsConfig, handler)
	}
	inner, err := v2ray.NewServerTransport(ctx, logger, options, tlsConfig, &sourceHandler{handler: handler})
	if err != nil || inner == nil {
		return inner, err
	}
	httpHandler, isHTTP := inner.(http.Handler)
	if !isHTTP {
		return inner, nil
	}
	server := &httpTransport{V2RayServerTransport: inner, tls: tlsConfig}
	server.server = &http.Server{
		ReadHeaderTimeout: C.TCPTimeout,
		MaxHeaderBytes:    http.DefaultMaxHeaderBytes,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			address := M.SocksaddrFromNet(conn.RemoteAddr()).Addr
			return WithSource(log.ContextWithNewID(ctx), func() netip.Addr { return address })
		},
	}
	var wrapped http.Handler = &peerHandler{inner: httpHandler}
	if options.Type == C.V2RayTransportTypeHTTP || options.Type == C.V2RayTransportTypeGRPC {
		idleTimeout := options.HTTPOptions.IdleTimeout
		if options.Type == C.V2RayTransportTypeGRPC {
			idleTimeout = options.GRPCOptions.IdleTimeout
		}
		h2 := &http2.Server{IdleTimeout: time.Duration(idleTimeout)}
		if err := http2.ConfigureServer(server.server, h2); err != nil {
			_ = inner.Close()
			return nil, err
		}
		wrapped = h2c.NewHandler(wrapped, h2)
		configureHTTPProtocols(tlsConfig)
	} else {
		server.server.TLSNextProto = map[string]func(*http.Server, *tls.STDConn, http.Handler){}
	}
	server.server.Handler = wrapped
	return server, nil
}

func configureHTTPProtocols(config tls.ServerConfig) {
	if config == nil {
		return
	}
	protocols := config.NextProtos()
	if len(protocols) == 0 {
		config.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
	} else if !common.Contains(protocols, http2.NextProtoTLS) {
		config.SetNextProtos(append([]string{http2.NextProtoTLS}, protocols...))
	}
}

type httpTransport struct {
	adapter.V2RayServerTransport
	server *http.Server
	tls    tls.ServerConfig
}

func (s *httpTransport) Serve(listener net.Listener) error {
	if s.tls != nil {
		listener = aTLS.NewListener(listener, s.tls)
	}
	return s.server.Serve(listener)
}

func (s *httpTransport) ServePacket(net.PacketConn) error { return os.ErrInvalid }

func (s *httpTransport) Close() error {
	return common.Close(s.server, s.V2RayServerTransport)
}

type verifiedSource interface{ SourceAddress() netip.Addr }

type peerConn struct {
	net.Conn
	address netip.Addr
}

func (c *peerConn) SourceAddress() netip.Addr { return c.address }
func (c *peerConn) Upstream() any             { return c.Conn }

type sourceHandler struct {
	handler adapter.V2RayServerTransportHandler
}

func (h *sourceHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if Source(ctx) == nil {
		ctx = WithSource(ctx, connectionSource(conn))
		if grpc, ok := common.Cast[*v2raygrpc.GRPCConn](conn); ok {
			if stream, ok := grpc.GunService.(interface{ Context() context.Context }); ok {
				if incoming, ok := metadata.FromIncomingContext(stream.Context()); ok {
					ctx = forwardedContext(ctx, incoming.Get("x-forwarded-for"))
				}
			}
		}
	}
	h.handler.NewConnectionEx(ctx, conn, source, destination, onClose)
}

func connectionSource(conn net.Conn) func() netip.Addr {
	if marked, ok := common.Cast[verifiedSource](conn); ok {
		return marked.SourceAddress
	}
	if grpc, ok := common.Cast[*v2raygrpc.GRPCConn](conn); ok {
		if stream, ok := grpc.GunService.(interface{ Context() context.Context }); ok {
			if p, ok := peer.FromContext(stream.Context()); ok {
				return func() netip.Addr { return M.SocksaddrFromNet(p.Addr).Addr }
			}
		}
		return func() netip.Addr { return netip.Addr{} }
	}
	return func() netip.Addr { return M.SocksaddrFromNet(conn.RemoteAddr()).Addr }
}

type peerHandler struct{ inner http.Handler }

func (h *peerHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	request = request.WithContext(forwardedContext(request.Context(), request.Header.Values("X-Forwarded-For")))
	source := Source(request.Context())
	address := netip.Addr{}
	if source != nil {
		address = source()
	}
	wrapped := &peerWriter{ResponseWriter: writer, address: address}
	if hijacker, ok := writer.(http.Hijacker); ok {
		h.inner.ServeHTTP(&peerHijacker{peerWriter: wrapped, hijacker: hijacker}, request)
		return
	}
	h.inner.ServeHTTP(wrapped, request)
}

type peerWriter struct {
	http.ResponseWriter
	address netip.Addr
}

func (w *peerWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *peerWriter) FlushError() error           { return http.NewResponseController(w.ResponseWriter).Flush() }
func (w *peerWriter) Flush()                      { _ = w.FlushError() }

type peerHijacker struct {
	*peerWriter
	hijacker http.Hijacker
}

func (w *peerHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buffer, err := w.hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	return &peerConn{Conn: conn, address: w.address}, buffer, nil
}
