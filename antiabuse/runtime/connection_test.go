package runtime

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alireza0/s-ui/core/connectionpolicy"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestCounterUnwrapCannotBypassExistingStreamGuard(t *testing.T) {
	r, c := newRuntime(t)
	left, right := net.Pipe()
	t.Cleanup(func() { _ = right.Close() })
	metadata := adapter.InboundContext{Inbound: "in", User: "user", Source: M.SocksaddrFrom(sourceB, 1)}
	guarded, err := r.Connection(context.Background(), left, metadata)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guarded.Close() })
	read, write := &atomic.Int64{}, &atomic.Int64{}
	counted := bufio.NewInt64CounterConn(guarded, []*atomic.Int64{read}, []*atomic.Int64{write})
	unwrapped, counters := N.UnwrapCountWriter(counted, nil)
	if unwrapped != guarded || len(counters) != 1 {
		t.Fatal("guard was bypassed by counter unwrap")
	}
	c.advance(61 * time.Second)
	decision(t, r, 1, []netip.Prefix{prefix(sourceA)}, []netip.Prefix{prefix(sourceB)})
	if _, err := unwrapped.Write([]byte{1}); !errors.Is(err, ErrDenied) {
		t.Fatalf("old copy loop bypassed admission: %v", err)
	}
	if write.Load() != 0 {
		t.Fatal("rejected bytes counted as successfully forwarded")
	}
}

func TestReadChecksAdmissionAfterBlockedReadResumes(t *testing.T) {
	r, _ := newRuntime(t)
	left, right := net.Pipe()
	t.Cleanup(func() { _ = right.Close() })
	metadata := adapter.InboundContext{Inbound: "in", User: "user", Source: M.SocksaddrFrom(sourceB, 1)}
	conn, err := r.Connection(context.Background(), left, metadata)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	result := make(chan error, 1)
	go func() {
		data := make([]byte, 1)
		n, err := conn.Read(data)
		if n != 0 {
			result <- errors.New("rejected inbound bytes forwarded")
			return
		}
		result <- err
	}()
	decision(t, r, 1, []netip.Prefix{prefix(sourceA)}, []netip.Prefix{prefix(sourceB)})
	if err := right.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _ = right.Write([]byte{1})
	if err := <-result; !errors.Is(err, ErrDenied) {
		t.Fatalf("read admission: %v", err)
	}
}

type memoryPacket struct {
	N.PacketConn
	writes int
	closed bool
}

func (p *memoryPacket) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	p.writes += buffer.Len()
	buffer.Release()
	return nil
}

func (p *memoryPacket) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	_, err := buffer.Write([]byte{1})
	return M.Socksaddr{}, err
}

func (p *memoryPacket) Close() error { p.closed = true; return nil }

func TestPacketPathsAndTrustedSource(t *testing.T) {
	r, _ := newRuntime(t)
	raw := &memoryPacket{}
	// Routing metadata may differ. Admission follows the separately bound peer.
	ctx := connectionpolicy.WithSource(context.Background(), func() netip.Addr { return sourceB })
	metadata := adapter.InboundContext{Inbound: "in", User: "user", Source: M.SocksaddrFrom(sourceA, 1)}
	conn, err := r.PacketConnection(ctx, raw, metadata)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	decision(t, r, 1, []netip.Prefix{prefix(sourceA)}, []netip.Prefix{prefix(sourceB)})
	buffer := buf.As([]byte{1})
	if err := conn.WritePacket(buffer, M.Socksaddr{}); !errors.Is(err, ErrDenied) || raw.writes != 0 {
		t.Fatal("packet writer bypassed policy")
	}
	buffer = buf.New()
	defer buffer.Release()
	if _, err := conn.ReadPacket(buffer); !errors.Is(err, ErrDenied) {
		t.Fatal("packet reader bypassed policy")
	}
}

var _ io.Writer = (*stream)(nil)
