package runtime

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type framedConn struct{ N.ExtendedConn }

func (*framedConn) FrontHeadroom() int  { return 2 }
func (*framedConn) RearHeadroom() int   { return 16 }
func (*framedConn) ReaderOverhead() int { return 9 }
func (*framedConn) ReaderMTU() int      { return 1500 }
func (*framedConn) WriterMTU() int      { return 1400 }
func (*framedConn) WriteBuffer(buffer *buf.Buffer) error {
	buffer.ExtendHeader(2)
	buffer.Release()
	return nil
}

func TestGuardPreservesProtocolBufferRequirements(t *testing.T) {
	r, _ := newRuntime(t)
	conn, err := r.Connection(context.Background(), &framedConn{}, adapter.InboundContext{
		Inbound: "in", User: "user", Source: M.SocksaddrFrom(sourceA, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	guarded := conn.(*stream)
	defer guarded.flow.Close()
	if N.CalculateFrontHeadroom(guarded) != 2 || N.CalculateRearHeadroom(guarded) != 16 ||
		N.CalculateReaderOverhead(guarded) != 9 || N.CalculateMTU(guarded, nil) != 1500 || N.CalculateMTU(nil, guarded) != 1400 {
		t.Fatal("guard discarded the framing requirements")
	}
	buffer := buf.New()
	buffer.Resize(N.CalculateFrontHeadroom(guarded), 1)
	buffer.Reserve(N.CalculateRearHeadroom(guarded))
	if err := guarded.WriteBuffer(buffer); err != nil {
		t.Fatal(err)
	}
}
