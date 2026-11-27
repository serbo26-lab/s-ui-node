package connectionpolicy

import (
	"context"
	"io"
	"net/netip"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/log"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/congestion_meta1"
	"github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/ntp"
)

func (h *naiveInbound) startHTTP3() (io.Closer, error) {
	if err := qtls.ConfigureHTTP3(h.tls); err != nil {
		return nil, err
	}
	if !common.Contains(h.tls.NextProtos(), http3.NextProtoH3) {
		h.tls.SetNextProtos(append(append([]string{}, h.tls.NextProtos()...), http3.NextProtoH3))
	}
	congestionControl, err := h.congestionControl()
	if err != nil {
		return nil, err
	}
	socket, err := h.listener.ListenUDP()
	if err != nil {
		return nil, err
	}
	listener, err := qtls.ListenEarly(socket, h.tls, &quic.Config{
		MaxIncomingStreams: 1 << 60, Allow0RTT: true, DisablePathManager: true,
	})
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	server := &http3.Server{Handler: h.handler,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			conn.SetCongestionControl(congestionControl(conn))
			return WithSource(log.ContextWithNewID(ctx), func() netip.Addr { return M.SocksaddrFromNet(conn.RemoteAddr()).Addr })
		},
	}
	go func() {
		err := server.ServeListener(listener)
		_ = socket.Close()
		if err != nil && !E.IsClosedOrCanceled(err) {
			h.logger.Error("naive http3 server closed: ", err)
		}
	}()
	return common.Closer(func() error { return common.Close(server, listener, socket) }), nil
}

func (h *naiveInbound) congestionControl() (func(*quic.Conn) congestion.CongestionControl, error) {
	now := ntp.TimeFuncFromContext(h.ctx)
	if now == nil {
		now = time.Now
	}
	switch h.options.QUICCongestionControl {
	case "", "bbr":
		return func(conn *quic.Conn) congestion.CongestionControl {
			return congestion_meta2.NewBbrSenderWithProfile(conn.InitialPacketSize(), congestion_meta2.ProfileStandard)
		}, nil
	case "cubic", "reno":
		return func(conn *quic.Conn) congestion.CongestionControl {
			return congestion_meta1.NewCubicSender(congestion_meta1.DefaultClock{TimeFunc: now}, conn.InitialPacketSize(), h.options.QUICCongestionControl == "reno")
		}, nil
	default:
		return nil, E.New("unknown quic congestion control: ", h.options.QUICCongestionControl)
	}
}
