package connectionpolicy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type naiveInbound struct {
	inbound.Adapter
	logger   log.ContextLogger
	listener *listener.Listener
	tls      tls.ServerConfig
	handler  http.Handler
	options  option.NaiveInboundOptions
}

func newNaiveInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NaiveInboundOptions) (adapter.Inbound, error) {
	if service.FromContext[Guard](ctx) == nil && !managedAuthentication(ctx) {
		return naive.NewInbound(ctx, router, logger, tag, options)
	}
	if common.Contains(options.Network.Build(), N.NetworkUDP) && (options.TLS == nil || !options.TLS.Enabled) {
		return nil, errors.New("TLS is required for QUIC server")
	}
	// Reuse the native authentication, padding and stream handler. Its listener
	// stays unopened; the outer server binds the peer before parsing headers.
	handlerOptions := options
	handlerOptions.TLS, handlerOptions.Network = nil, N.NetworkTCP
	inner, err := naive.NewInbound(ctx, router, logger, tag, handlerOptions)
	if err != nil {
		return nil, err
	}
	handler := inner.(http.Handler)
	if managedAuthentication(ctx) && len(options.Users) == 0 {
		handler = http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusProxyAuthRequired)
		})
	}
	h := &naiveInbound{Adapter: inbound.NewAdapter(C.TypeNaive, tag), logger: logger,
		handler: &peerHandler{inner: handler}, options: options}
	if options.TLS != nil {
		h.tls, err = tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
	}
	h.listener = listener.New(listener.Options{Context: ctx, Logger: logger, Listen: options.ListenOptions})
	return h, nil
}

func (h *naiveInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tls != nil {
		if err := h.tls.Start(); err != nil {
			return err
		}
		scope.Add(h.tls.Close)
		configureHTTPProtocols(h.tls)
	}
	scope.Add(h.listener.Close)
	network := h.options.Network.Build()
	if common.Contains(network, N.NetworkUDP) {
		closer, err := h.startHTTP3(scope.Context())
		if err != nil {
			if len(network) == 1 {
				return err
			}
			h.logger.Warn("naive http3 disabled: ", err)
		} else {
			scope.Add(closer.Close)
		}
	}
	if common.Contains(network, N.NetworkTCP) {
		return h.startHTTP(scope)
	}
	return nil
}

func (h *naiveInbound) startHTTP(scope *adapter.Scope) error {
	socket, err := h.listener.ListenTCP()
	if err != nil {
		return err
	}
	server := &http.Server{ReadHeaderTimeout: C.TCPTimeout,
		Handler:     h2c.NewHandler(h.handler, &http2.Server{}),
		BaseContext: func(net.Listener) context.Context { return scope.Context() },
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			address := M.SocksaddrFromNet(conn.RemoteAddr()).Addr
			return WithSource(log.ContextWithNewID(ctx), func() netip.Addr { return address })
		},
	}
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		return err
	}
	var stream net.Listener = socket
	if h.tls != nil {
		stream = aTLS.NewListener(stream, h.tls)
	}
	scope.Add(server.Close)
	go func() {
		if err := server.Serve(stream); err != nil && !errors.Is(err, http.ErrServerClosed) {
			h.logger.Error("naive http server closed: ", err)
		}
	}()
	return nil
}
