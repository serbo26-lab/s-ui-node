package runtime

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
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

type blockedWriter struct {
	net.Conn
	started           chan struct{}
	interrupted       chan struct{}
	once              sync.Once
	writing           atomic.Bool
	closedDuringWrite atomic.Bool
	closes            atomic.Int32
}

func (c *blockedWriter) Write([]byte) (int, error) {
	c.writing.Store(true)
	close(c.started)
	<-c.interrupted
	c.writing.Store(false)
	return 0, os.ErrDeadlineExceeded
}

func (c *blockedWriter) SetWriteDeadline(time.Time) error {
	c.once.Do(func() { close(c.interrupted) })
	return nil
}

func (c *blockedWriter) Close() error {
	c.closedDuringWrite.Store(c.writing.Load())
	c.closes.Add(1)
	return c.Conn.Close()
}

func TestStreamCloseInterruptsBlockedWriterBeforeClosingProtocolState(t *testing.T) {
	r, _ := newRuntime(t)
	left, right := net.Pipe()
	t.Cleanup(func() { _ = right.Close() })
	raw := &blockedWriter{Conn: left, started: make(chan struct{}), interrupted: make(chan struct{})}
	conn, err := r.Connection(context.Background(), raw, adapter.InboundContext{Inbound: "in", User: "user", Source: M.SocksaddrFrom(sourceA, 1)})
	if err != nil {
		t.Fatal(err)
	}
	written, closed := make(chan error, 1), make(chan error, 1)
	go func() { _, err := conn.Write([]byte{42}); written <- err }()
	<-raw.started
	go func() { closed <- conn.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close waited for a write without interrupting it")
	}
	if !errors.Is(<-written, os.ErrDeadlineExceeded) || raw.closedDuringWrite.Load() {
		t.Fatal("protocol state closed during write")
	}
	if err := conn.Close(); err != nil || raw.closes.Load() != 1 {
		t.Fatal("duplicate underlying close", err)
	}
}

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
