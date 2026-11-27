package connectionpolicy

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	boxhttp "github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/http"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/service"
)

// Bind the peer before HTTP authentication and forwarding can replace routing
// metadata or move a request onto an internal pipe.
func RegisterHTTPInbounds(registry *inbound.Registry) {
	inbound.Register[option.HTTPMixedInboundOptions](registry, C.TypeHTTP, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HTTPMixedInboundOptions) (adapter.Inbound, error) {
		if service.FromContext[Guard](ctx) == nil {
			return boxhttp.NewInbound(ctx, router, logger, tag, options)
		}
		return newProxyInbound(ctx, router, logger, tag, C.TypeHTTP, options)
	})
	inbound.Register[option.HTTPMixedInboundOptions](registry, C.TypeMixed, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HTTPMixedInboundOptions) (adapter.Inbound, error) {
		if service.FromContext[Guard](ctx) == nil {
			return mixed.NewInbound(ctx, router, logger, tag, options)
		}
		return newProxyInbound(ctx, router, logger, tag, C.TypeMixed, options)
	})
	inbound.Register[option.NaiveInboundOptions](registry, C.TypeNaive, newNaiveInbound)
}

type proxyInbound struct {
	inbound.Adapter
	router        adapter.ConnectionRouterEx
	logger        log.ContextLogger
	listener      *listener.Listener
	authenticator *auth.Authenticator
	tls           tls.ServerConfig
	udpTimeout    time.Duration
}

func newProxyInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag, kind string, options option.HTTPMixedInboundOptions) (adapter.Inbound, error) {
	h := &proxyInbound{Adapter: inbound.NewAdapter(kind, tag), router: uot.NewRouter(router, logger),
		logger: logger, authenticator: auth.NewAuthenticator(options.Users), udpTimeout: time.Duration(options.UDPTimeout)}
	if h.udpTimeout == 0 {
		h.udpTimeout = C.UDPTimeout
	}
	if options.TLS != nil {
		var err error
		h.tls, err = tls.NewServerWithOptions(tls.ServerOptions{Context: ctx, Logger: logger,
			Options: common.PtrValueOrDefault(options.TLS), KTLSCompatible: true})
		if err != nil {
			return nil, err
		}
	}
	h.listener = listener.New(listener.Options{Context: ctx, Logger: logger, Network: []string{N.NetworkTCP},
		Listen: options.ListenOptions, ConnectionHandler: h, SetSystemProxy: options.SetSystemProxy, SystemProxySOCKS: kind == C.TypeMixed})
	return h, nil
}

func (h *proxyInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tls != nil {
		if err := h.tls.Start(); err != nil {
			return err
		}
		scope.Add(h.tls.Close)
	}
	if err := h.listener.Start(); err != nil {
		return err
	}
	scope.Add(h.listener.Close)
	return nil
}

func (h *proxyInbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = bindPeer(ctx, conn, metadata.Source.Addr)
	err := h.handle(ctx, conn, metadata, onClose)
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil && !E.IsClosedOrCanceled(err) {
		h.logger.ErrorContext(ctx, E.Cause(err, "process proxy connection"))
	}
}

func bindPeer(ctx context.Context, conn net.Conn, fallback netip.Addr) context.Context {
	if Source(ctx) != nil {
		return ctx
	}
	address := M.SocksaddrFromNet(conn.RemoteAddr()).Addr
	if !address.IsValid() {
		address = fallback
	}
	return WithSource(ctx, func() netip.Addr { return address })
}

func (h *proxyInbound) handle(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	if h.tls != nil {
		secured, err := tls.ServerHandshake(ctx, conn, h.tls)
		if err != nil {
			return err
		}
		conn = secured
	}
	reader := bufio.NewReader(conn)
	handler := adapter.NewUpstreamHandler(metadata, h.connection, h.packetConnection)
	if h.Type() == C.TypeMixed {
		first, err := reader.Peek(1)
		if err != nil {
			return err
		}
		if first[0] == 4 || first[0] == 5 {
			return socks.HandleConnectionEx(ctx, conn, reader, h.authenticator, handler, h.listener, h.udpTimeout, metadata.Source, onClose)
		}
	}
	return http.HandleConnectionEx(ctx, conn, reader, h.authenticator, handler, metadata.Source, onClose)
}

func (h *proxyInbound) metadata(ctx context.Context, metadata adapter.InboundContext) adapter.InboundContext {
	metadata.Inbound, metadata.InboundType = h.Tag(), h.Type()
	metadata.User, _ = auth.UserFromContext[string](ctx)
	return metadata
}

func (h *proxyInbound) connection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	h.router.RouteConnectionEx(ctx, conn, h.metadata(ctx, metadata), onClose)
}

func (h *proxyInbound) packetConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	h.router.RoutePacketConnectionEx(ctx, conn, h.metadata(ctx, metadata), onClose)
}

var _ adapter.TCPInjectableInbound = (*proxyInbound)(nil)
