package nodeagent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/alireza0/s-ui/core"
	socksproxy "golang.org/x/net/proxy"
)

func freeV2Port(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func TestV2ActualVLESSTrafficDeniedAfterRevokeAndRestart(t *testing.T) {
	serverPort, clientPort := freeV2Port(t), freeV2Port(t)
	state := t.TempDir()
	d := Deployment{NodeID: 7, Revision: 1, Users: []Access{{Name: "client/1"}}, Config: json.RawMessage(fmt.Sprintf(`{"inbounds":[{"type":"vless","tag":"vpn","listen":"127.0.0.1","listen_port":%d,"users":[{"name":"client/1","uuid":"11111111-1111-4111-8111-111111111111"}]}],"outbounds":[{"type":"direct","tag":"direct"}]}`, serverPort))}
	legacy := FileStore{Directory: state}
	if err := legacy.Save(d); err != nil {
		t.Fatal(err)
	}
	m := NewManagerV2(7, FileStoreV2{Directory: state}, NewCoreRuntimeWithState(state))
	if err := m.Restore(legacy); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "authenticated-v2") }))
	defer backend.Close()
	proxy := core.NewCoreWithContext(context.Background())
	defer proxy.Stop()
	config := []byte(fmt.Sprintf(`{"inbounds":[{"type":"socks","tag":"socks","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"vless","tag":"proxy","server":"127.0.0.1","server_port":%d,"uuid":"11111111-1111-4111-8111-111111111111"}],"route":{"final":"proxy"}}`, clientPort, serverPort))
	if err := proxy.Start(config); err != nil {
		t.Fatal(err)
	}
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", clientPort))
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	fetch := func() bool {
		response, err := client.Get(backend.URL)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return string(body) == "authenticated-v2"
	}
	if !fetch() {
		t.Fatal("real VLESS traffic failed before revoke")
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	dialer, err := socksproxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), nil, socksproxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	openSession := func() net.Conn {
		t.Helper()
		conn, err := dialer.Dial("tcp", echo.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
			t.Fatal("persistent VLESS session failed", err)
		}
		_ = conn.SetDeadline(time.Time{})
		return conn
	}
	assertClosed := func(conn net.Conn) {
		t.Helper()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write([]byte("ping"))
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err == nil {
			t.Fatal("old authenticated session survived access generation change")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("session remained open after access revocation")
		}
	}
	oldSession := openSession()
	deny := AccessSnapshot{NodeID: 7, Epoch: m.Status().Epoch, Revision: 1, Clients: []Grant{}}
	if err := m.ApplyAccess(deny); err != nil {
		t.Fatal(err)
	}
	if fetch() {
		t.Fatal("old VLESS credential still authenticated after revoke")
	}
	assertClosed(oldSession)
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	next := NewManagerV2(7, FileStoreV2{Directory: state}, NewCoreRuntimeWithState(state))
	defer next.Close()
	if err := next.Restore(legacy); err != nil {
		t.Fatal(err)
	}
	if fetch() {
		t.Fatal("restart re-enabled old VLESS credential")
	}
	_, grant, err := ImportV1(d, next.Status().Epoch)
	if err != nil {
		t.Fatal(err)
	}
	grant.Revision = 2
	grant.Clients[0].Name = "client/1/g2"
	if err := next.ApplyAccess(grant); err != nil {
		t.Fatal(err)
	}
	if !fetch() {
		t.Fatal("explicit re-enable did not restore valid traffic")
	}
	oldSession = openSession()
	grant.Revision = 3
	grant.Clients[0].Name = "client/1/g3"
	if err := next.ApplyAccess(grant); err != nil {
		t.Fatal(err)
	}
	assertClosed(oldSession)
	if !fetch() {
		t.Fatal("generation change broke fresh valid sessions")
	}
}
