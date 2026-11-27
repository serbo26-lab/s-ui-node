package connectionpolicy

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// Guard is optional. Protocols do not depend on the implementation or its rules.
type Guard interface {
	Connection(context.Context, net.Conn, adapter.InboundContext) (net.Conn, error)
	PacketConnection(context.Context, N.PacketConn, adapter.InboundContext) (N.PacketConn, error)
}

func WithGuard(ctx context.Context, guard Guard) context.Context {
	return service.ContextWith[Guard](ctx, guard)
}

type sourceKey struct{}

// WithSource carries the physical peer independently of routing metadata. A
// provider may follow a QUIC connection's current verified remote address.
func WithSource(ctx context.Context, source func() netip.Addr) context.Context {
	return context.WithValue(ctx, sourceKey{}, source)
}

func Source(ctx context.Context) func() netip.Addr {
	source, _ := ctx.Value(sourceKey{}).(func() netip.Addr)
	return source
}

func WrapRouter(ctx context.Context, router adapter.Router) adapter.Router {
	guard := service.FromContext[Guard](ctx)
	if guard == nil {
		return router
	}
	return &guardedRouter{Router: router, guard: guard}
}

type guardedRouter struct {
	adapter.Router
	guard Guard
}

func (r *guardedRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	wrapped, err := r.guard.Connection(ctx, conn, metadata)
	if err != nil {
		_ = conn.Close()
		return err
	}
	return r.Router.RouteConnection(ctx, wrapped, metadata)
}

func (r *guardedRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	wrapped, err := r.guard.PacketConnection(ctx, conn, metadata)
	if err != nil {
		_ = conn.Close()
		return err
	}
	return r.Router.RoutePacketConnection(ctx, wrapped, metadata)
}

func (r *guardedRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	wrapped, err := r.guard.Connection(ctx, conn, metadata)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	r.Router.RouteConnectionEx(ctx, wrapped, metadata, onClose)
}

func (r *guardedRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	wrapped, err := r.guard.PacketConnection(ctx, conn, metadata)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	r.Router.RoutePacketConnectionEx(ctx, wrapped, metadata, onClose)
}
