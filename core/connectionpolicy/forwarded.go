package connectionpolicy

import (
	"context"
	"net/netip"
	"slices"

	"github.com/sagernet/sing/service"
)

type forwardedGuard interface {
	ForwardedSource(netip.Addr, []string) netip.Addr
}

func forwardedContext(ctx context.Context, headers []string) context.Context {
	guard, ok := service.FromContext[Guard](ctx).(forwardedGuard)
	peer := Source(ctx)
	if !ok || peer == nil {
		return ctx
	}
	values := slices.Clone(headers)
	return WithSource(ctx, func() netip.Addr { return guard.ForwardedSource(peer(), values) })
}
