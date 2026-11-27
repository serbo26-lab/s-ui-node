package connectionpolicy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

type sourceResult struct{ physical, routing netip.Addr }

type captureSource struct{ result chan sourceResult }

func (h captureSource) NewConnectionEx(ctx context.Context, conn net.Conn, source, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	address := netip.Addr{}
	if getter := Source(ctx); getter != nil {
		address = getter()
	}
	h.result <- sourceResult{physical: address, routing: source.Addr}
	_ = conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

func TestHTTPPhysicalPeerSurvivesForwardedHeaderAndContextCopies(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "h2c"}[h2], func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			result := make(chan sourceResult, 1)
			ctx := WithGuard(context.Background(), rejectingGuard{})
			transport, err := NewServerTransport(ctx, log.NewNOPFactory().Logger(),
				option.V2RayTransportOptions{Type: "http", HTTPOptions: option.V2RayHTTPOptions{Path: "/"}}, nil, captureSource{result})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = transport.Close() })
			go func() { _ = transport.Serve(listener) }()
			client := &http.Client{Timeout: 3 * time.Second}
			if h2 {
				client.Transport = &http2.Transport{AllowHTTP: true,
					DialTLS: func(_, address string, _ *tls.Config) (net.Conn, error) {
						return net.DialTimeout("tcp", address, time.Second)
					}}
			}
			t.Cleanup(client.CloseIdleConnections)
			request, err := http.NewRequest(http.MethodPost, "http://"+listener.Addr().String()+"/", strings.NewReader("probe"))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Forwarded-For", "192.0.2.99")
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			select {
			case got := <-result:
				if got.physical != netip.MustParseAddr("127.0.0.1") || got.routing != netip.MustParseAddr("192.0.2.99") {
					t.Fatalf("peer provenance or routing changed: %+v", got)
				}
			case <-time.After(time.Second):
				t.Fatal("HTTP source not delivered")
			}
		})
	}
}
