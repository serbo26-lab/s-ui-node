package runtime

import (
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (c *packet) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	inner, ok := bufio.CreatePacketBatchWriter(c.PacketConn)
	if !ok {
		return nil, false
	}
	return &packetBatchWriter{inner: inner, packet: c}, true
}

type packetBatchWriter struct {
	inner  N.PacketBatchWriter
	packet *packet
}

func (w *packetBatchWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	n := buf.LenMulti(buffers)
	if n > 0 && !w.packet.flow.Permit() {
		buf.ReleaseMulti(buffers)
		_ = w.packet.Close()
		return ErrDenied
	}
	if err := w.inner.WritePacketBatch(buffers, destinations); err != nil {
		return err
	}
	w.packet.flow.Activity(n)
	return nil
}

func (c *packet) CreateConnectedPacketBatchWriter() (N.ConnectedPacketBatchWriter, bool) {
	inner, ok := bufio.CreateConnectedPacketBatchWriter(c.PacketConn)
	if !ok {
		return nil, false
	}
	return &connectedPacketWriter{inner: inner, packet: c}, true
}

type connectedPacketWriter struct {
	inner  N.ConnectedPacketBatchWriter
	packet *packet
}

func (w *connectedPacketWriter) WriteConnectedPacketBatch(buffers []*buf.Buffer) error {
	n := buf.LenMulti(buffers)
	if n > 0 && !w.packet.flow.Permit() {
		buf.ReleaseMulti(buffers)
		_ = w.packet.Close()
		return ErrDenied
	}
	if err := w.inner.WriteConnectedPacketBatch(buffers); err != nil {
		return err
	}
	w.packet.flow.Activity(n)
	return nil
}
