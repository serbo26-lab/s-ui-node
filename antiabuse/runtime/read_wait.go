package runtime

import (
	"io"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type readGate struct {
	flow   *Flow
	closer io.Closer
}

func (g readGate) buffers(buffers []*buf.Buffer) error {
	n := buf.LenMulti(buffers)
	if n > 0 && !g.flow.Permit() {
		buf.ReleaseMulti(buffers)
		_ = g.closer.Close()
		return ErrDenied
	}
	g.flow.Activity(n)
	return nil
}

func (c *stream) CreateReadWaiter() (N.ReadWaiter, bool) {
	inner, ok := bufio.CreateReadWaiter(c.ExtendedConn)
	if !ok {
		return nil, false
	}
	return &streamReadWaiter{ReadWaiter: inner, gate: readGate{c.flow, c}}, true
}

type streamReadWaiter struct {
	N.ReadWaiter
	gate readGate
}

func (w *streamReadWaiter) WaitReadBuffer() (*buf.Buffer, error) {
	buffer, err := w.ReadWaiter.WaitReadBuffer()
	if err != nil {
		return buffer, err
	}
	if err := w.gate.buffers([]*buf.Buffer{buffer}); err != nil {
		return nil, err
	}
	return buffer, nil
}

func (c *stream) CreateVectorisedReadWaiter() (N.VectorisedReadWaiter, bool) {
	inner, ok := bufio.CreateVectorisedReadWaiter(c.ExtendedConn)
	if !ok {
		return nil, false
	}
	return &streamVectorWaiter{VectorisedReadWaiter: inner, gate: readGate{c.flow, c}}, true
}

type streamVectorWaiter struct {
	N.VectorisedReadWaiter
	gate readGate
}

func (w *streamVectorWaiter) WaitReadBuffers() ([]*buf.Buffer, error) {
	buffers, err := w.VectorisedReadWaiter.WaitReadBuffers()
	if err != nil {
		return buffers, err
	}
	if err := w.gate.buffers(buffers); err != nil {
		return nil, err
	}
	return buffers, nil
}

func (c *packet) CreateReadWaiter() (N.PacketReadWaiter, bool) {
	inner, ok := bufio.CreatePacketReadWaiter(c.PacketConn)
	if !ok {
		return nil, false
	}
	return &packetReadWaiter{PacketReadWaiter: inner, gate: readGate{c.flow, c}}, true
}

type packetReadWaiter struct {
	N.PacketReadWaiter
	gate readGate
}

func (w *packetReadWaiter) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	buffer, destination, err := w.PacketReadWaiter.WaitReadPacket()
	if err != nil {
		return buffer, destination, err
	}
	if err := w.gate.buffers([]*buf.Buffer{buffer}); err != nil {
		return nil, destination, err
	}
	return buffer, destination, nil
}

func (c *packet) CreatePacketBatchReadWaiter() (N.PacketBatchReadWaiter, bool) {
	inner, ok := bufio.CreatePacketBatchReadWaiter(c.PacketConn)
	if !ok {
		return nil, false
	}
	return &packetBatchWaiter{PacketBatchReadWaiter: inner, gate: readGate{c.flow, c}}, true
}

type packetBatchWaiter struct {
	N.PacketBatchReadWaiter
	gate readGate
}

func (w *packetBatchWaiter) WaitReadPackets() ([]*buf.Buffer, []M.Socksaddr, error) {
	buffers, destinations, err := w.PacketBatchReadWaiter.WaitReadPackets()
	if err != nil {
		return buffers, destinations, err
	}
	if err := w.gate.buffers(buffers); err != nil {
		return nil, nil, err
	}
	return buffers, destinations, nil
}

func (c *packet) CreateConnectedPacketBatchReadWaiter() (N.ConnectedPacketBatchReadWaiter, bool) {
	inner, ok := bufio.CreateConnectedPacketBatchReadWaiter(c.PacketConn)
	if !ok {
		return nil, false
	}
	return &connectedPacketWaiter{ConnectedPacketBatchReadWaiter: inner, gate: readGate{c.flow, c}}, true
}

type connectedPacketWaiter struct {
	N.ConnectedPacketBatchReadWaiter
	gate readGate
}

func (w *connectedPacketWaiter) WaitReadConnectedPackets() ([]*buf.Buffer, M.Socksaddr, error) {
	buffers, destination, err := w.ConnectedPacketBatchReadWaiter.WaitReadConnectedPackets()
	if err != nil {
		return buffers, destination, err
	}
	if err := w.gate.buffers(buffers); err != nil {
		return nil, destination, err
	}
	return buffers, destination, nil
}
