package runtime

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alireza0/s-ui/core/connectionpolicy"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ connectionpolicy.Guard = (*Runtime)(nil)

func (r *Runtime) open(ctx context.Context, metadata adapter.InboundContext) (*Flow, error) {
	source := connectionpolicy.Source(ctx)
	if source == nil {
		source = func() netip.Addr { return metadata.Source.Addr }
	}
	return r.Open(Identity{Inbound: metadata.Inbound, User: metadata.User}, source)
}

func (r *Runtime) Connection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) (net.Conn, error) {
	flow, err := r.open(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return &stream{ExtendedConn: bufio.NewExtendedConn(conn), flow: flow}, nil
}

func (r *Runtime) PacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) (N.PacketConn, error) {
	flow, err := r.open(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return &packet{PacketConn: conn, flow: flow}, nil
}

// The guard remains inside counter unwraps. Exposing the underlying reader
// would let an existing copy loop bypass a later enable or idle re-admission.
type stream struct {
	N.ExtendedConn
	flow      *Flow
	writeMu   sync.Mutex
	closeOnce sync.Once
	closed    atomic.Bool
	closeErr  error
}

func (c *stream) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.flow.Close()
		// Interrupt a blocked write before waiting for protocol state to settle.
		// Logical transports without deadlines retain their native stream close.
		if c.ExtendedConn.SetWriteDeadline(time.Now()) == nil {
			c.writeMu.Lock()
			defer c.writeMu.Unlock()
		}
		c.closeErr = c.ExtendedConn.Close()
	})
	return c.closeErr
}

func (c *stream) Read(data []byte) (int, error) {
	n, err := c.ExtendedConn.Read(data)
	if n > 0 && !c.flow.Permit() {
		_ = c.Close()
		return 0, ErrDenied
	}
	c.flow.Activity(n)
	return n, err
}

func (c *stream) ReadBuffer(buffer *buf.Buffer) error {
	before := buffer.Len()
	if err := c.ExtendedConn.ReadBuffer(buffer); err != nil {
		return err
	}
	n := buffer.Len() - before
	if n > 0 && !c.flow.Permit() {
		_ = c.Close()
		return ErrDenied
	}
	c.flow.Activity(n)
	return nil
}

func (c *stream) Write(data []byte) (int, error) {
	if len(data) > 0 && !c.flow.Permit() {
		_ = c.Close()
		return 0, ErrDenied
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.ExtendedConn.Write(data)
	c.flow.Activity(n)
	return n, err
}

func (c *stream) WriteBuffer(buffer *buf.Buffer) error {
	n := buffer.Len()
	if n > 0 && !c.flow.Permit() {
		buffer.Release()
		_ = c.Close()
		return ErrDenied
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		buffer.Release()
		return net.ErrClosed
	}
	if err := c.ExtendedConn.WriteBuffer(buffer); err != nil {
		return err
	}
	c.flow.Activity(n)
	return nil
}

func (c *stream) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	writer, ok := bufio.CreateVectorisedWriter(c.ExtendedConn)
	if !ok {
		return nil, false
	}
	return &vectorWriter{writer: writer, stream: c}, true
}

type vectorWriter struct {
	writer N.VectorisedWriter
	stream *stream
}

func (w *vectorWriter) WriteVectorised(buffers []*buf.Buffer) error {
	n := buf.LenMulti(buffers)
	if n > 0 && !w.stream.flow.Permit() {
		buf.ReleaseMulti(buffers)
		_ = w.stream.Close()
		return ErrDenied
	}
	w.stream.writeMu.Lock()
	defer w.stream.writeMu.Unlock()
	if w.stream.closed.Load() {
		buf.ReleaseMulti(buffers)
		return net.ErrClosed
	}
	if err := w.writer.WriteVectorised(buffers); err != nil {
		return err
	}
	w.stream.flow.Activity(n)
	return nil
}

type packet struct {
	N.PacketConn
	flow *Flow
}

func (c *packet) Close() error {
	c.flow.Close()
	return c.PacketConn.Close()
}

func (c *packet) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	before := buffer.Len()
	destination, err := c.PacketConn.ReadPacket(buffer)
	if err != nil {
		return destination, err
	}
	n := buffer.Len() - before
	if n > 0 && !c.flow.Permit() {
		_ = c.Close()
		return destination, ErrDenied
	}
	c.flow.Activity(n)
	return destination, nil
}

func (c *packet) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	n := buffer.Len()
	if n > 0 && !c.flow.Permit() {
		buffer.Release()
		_ = c.Close()
		return ErrDenied
	}
	if err := c.PacketConn.WritePacket(buffer, destination); err != nil {
		return err
	}
	c.flow.Activity(n)
	return nil
}
