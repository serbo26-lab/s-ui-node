package connectionpolicy

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

type rejectingGuard struct{}

var rejection = errors.New("rejected")

func (rejectingGuard) Connection(context.Context, net.Conn, adapter.InboundContext) (net.Conn, error) {
	return nil, rejection
}

func (rejectingGuard) PacketConnection(context.Context, N.PacketConn, adapter.InboundContext) (N.PacketConn, error) {
	return nil, rejection
}

type recordingRouter struct {
	adapter.Router
	calls int
}

func (r *recordingRouter) RouteConnection(context.Context, net.Conn, adapter.InboundContext) error {
	r.calls++
	return nil
}

func (r *recordingRouter) RoutePacketConnection(context.Context, N.PacketConn, adapter.InboundContext) error {
	r.calls++
	return nil
}

func (r *recordingRouter) RouteConnectionEx(context.Context, net.Conn, adapter.InboundContext, N.CloseHandlerFunc) {
	r.calls++
}

func (r *recordingRouter) RoutePacketConnectionEx(context.Context, N.PacketConn, adapter.InboundContext, N.CloseHandlerFunc) {
	r.calls++
}

type packetConn struct {
	N.PacketConn
	closed bool
}

func (c *packetConn) Close() error { c.closed = true; return nil }

func TestOptionalGuardLeavesOriginalRouter(t *testing.T) {
	inner := &recordingRouter{}
	if WrapRouter(context.Background(), inner) != inner {
		t.Fatal("missing optional guard changed router")
	}
}

func TestAllRouterEntriesRejectBeforeOutboundAndCompleteCallback(t *testing.T) {
	for _, extended := range []bool{false, true} {
		for _, packet := range []bool{false, true} {
			testRejectedRoute(t, extended, packet)
		}
	}
}

func testRejectedRoute(t *testing.T, extended, packet bool) {
	t.Helper()
	inner := &recordingRouter{}
	ctx := WithGuard(context.Background(), rejectingGuard{})
	router := WrapRouter(ctx, inner)
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	udp := &packetConn{}
	callbacks := 0
	onClose := func(err error) {
		callbacks++
		if !errors.Is(err, rejection) {
			t.Errorf("wrong close reason: %v", err)
		}
	}
	var err error
	metadata := adapter.InboundContext{}
	switch {
	case packet && extended:
		router.RoutePacketConnectionEx(ctx, udp, metadata, onClose)
	case packet:
		err = router.RoutePacketConnection(ctx, udp, metadata)
	case extended:
		router.RouteConnectionEx(ctx, left, metadata, onClose)
	default:
		err = router.RouteConnection(ctx, left, metadata)
	}
	if inner.calls != 0 || !extended && !errors.Is(err, rejection) || extended && callbacks != 1 || packet && !udp.closed {
		t.Fatalf("outbound=%d callback=%d err=%v", inner.calls, callbacks, err)
	}
}
