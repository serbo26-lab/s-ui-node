//go:build with_quic

package connectionpolicy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alireza0/s-ui/antiabuse/engine"
	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/core"
	"github.com/alireza0/s-ui/core/connectionpolicy"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	M "github.com/sagernet/sing/common/metadata"
)

func TestNaiveHTTP3TracksLiveQUICRebinding(t *testing.T) {
	runtime, err := ipruntime.New(engine.DefaultProfile(), nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime.SetUsers(map[ipruntime.Identity]string{{Inbound: "access", User: "user"}: "client"})
	runtime.SetEnabled(true)
	serverTLS, _ := testTLS(t)
	port := unusedPort(t)
	server := core.NewCoreWithContext(connectionpolicy.WithGuard(context.Background(), runtime))
	runCore(t, server, []any{map[string]any{"type": "naive", "tag": "access", "listen": "127.0.0.1", "listen_port": port,
		"network": "udp", "tls": serverTLS, "users": []any{map[string]any{"username": "user", "password": "test-only"}}}},
		[]any{map[string]any{"type": "direct", "tag": "direct"}})
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(serverTLS["certificate"].(string))) {
		t.Fatal("test certificate invalid")
	}
	socket := &rebindingSocket{}
	socket.rebind(t, "127.0.0.1")
	initial := &quic.Transport{Conn: socket}
	t.Cleanup(func() { _ = initial.Close(); _ = socket.Close() })
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "test.example", MinVersion: tls.VersionTLS13},
		Dial: func(ctx context.Context, address string, config *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			remote, err := net.ResolveUDPAddr("udp", address)
			if err != nil {
				return nil, err
			}
			return initial.DialEarly(ctx, remote, config, quicConfig)
		}}
	t.Cleanup(func() { _ = transport.Close() })
	echo, _ := echoServer(t)
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = writer.Close(); _ = reader.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://127.0.0.1:"+strconv.Itoa(int(port)), reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("-connect-authority", echo)
	request.Header.Set("Padding", "test")
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:test-only")))
	request.Header.Set("X-Forwarded-For", "192.0.2.99")
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	if response.StatusCode != http.StatusOK {
		t.Fatal("HTTP3 CONNECT failed", response.StatusCode)
	}
	if _, err := writer.Write([]byte{0, 1, 0, 42}); err != nil {
		t.Fatal(err)
	}
	assertPaddingEcho(t, response.Body)
	assertPhysicalReport(t, runtime)
	socket.rebind(t, "127.0.0.2")
	if _, err := writer.Write([]byte{0, 1, 0, 42}); err != nil {
		t.Fatal(err)
	}
	assertPaddingEcho(t, response.Body)
	state := runtime.Report("local").Snapshot
	for _, entry := range state.Entries {
		if entry.Address == netip.MustParseAddr("127.0.0.2") && entry.ActivityAge != nil {
			return
		}
	}
	t.Fatalf("migrated useful stream retained its old source: %+v", state)
}

func testTLS(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"test.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return map[string]any{"enabled": true, "server_name": "test.example", "certificate": cert,
			"key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))},
		map[string]any{"enabled": true, "server_name": "test.example", "certificate": cert}
}

// Simulate NAT rebinding without opening a new QUIC or application session.
type rebindingSocket struct {
	mu   sync.RWMutex
	conn *net.UDPConn
}

func (s *rebindingSocket) current() *net.UDPConn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.conn
}

func (s *rebindingSocket) rebind(t *testing.T, address string) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(address)})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.conn
	s.conn = conn
	if old != nil {
		_ = old.Close()
	}
}

func (s *rebindingSocket) ReadFrom(data []byte) (int, net.Addr, error) {
	for {
		conn := s.current()
		n, address, err := conn.ReadFrom(data)
		if err != nil && conn != s.current() {
			continue
		}
		return n, address, err
	}
}

func (s *rebindingSocket) WriteTo(data []byte, address net.Addr) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.conn.WriteTo(data, address)
}

func (s *rebindingSocket) Close() error                      { return s.current().Close() }
func (s *rebindingSocket) LocalAddr() net.Addr               { return s.current().LocalAddr() }
func (s *rebindingSocket) SetDeadline(value time.Time) error { return s.current().SetDeadline(value) }
func (s *rebindingSocket) SetReadDeadline(value time.Time) error {
	return s.current().SetReadDeadline(value)
}
func (s *rebindingSocket) SetWriteDeadline(value time.Time) error {
	return s.current().SetWriteDeadline(value)
}

func runCore(t *testing.T, instance *core.Core, inbounds, outbounds []any) {
	t.Helper()
	config, err := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "inbounds": inbounds, "outbounds": outbounds})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Stop() })
}

func TestNativeProxyProtocolsObserveAndRecheckUsefulStreams(t *testing.T) {
	for _, name := range []string{"vless", "vmess", "trojan", "anytls", "hysteria", "hysteria2", "tuic",
		"shadowsocks", "shadowsocks-2022", "snell", "vless-ws", "vless-httpupgrade", "vless-http", "vless-grpc", "vless-quic", "vless-mux"} {
		t.Run(name, func(t *testing.T) { testNativeProxy(t, name) })
	}
}

func TestNativeProxyDatagramsObserveAndRecheckAdmission(t *testing.T) {
	for _, name := range []string{"vless", "vmess", "shadowsocks", "shadowsocks-2022", "hysteria", "hysteria2", "tuic"} {
		t.Run(name, func(t *testing.T) { testNativeDatagrams(t, name) })
	}
}

func TestLiveHTTPTransportsReevaluateTrustedProxySources(t *testing.T) {
	for _, name := range []string{"vless-ws", "vless-httpupgrade", "vless-http"} {
		t.Run(name, func(t *testing.T) {
			runtime, err := ipruntime.New(engine.DefaultProfile(), nil)
			if err != nil {
				t.Fatal(err)
			}
			runtime.SetUsers(map[ipruntime.Identity]string{{Inbound: "access", User: "user"}: "client"})
			runtime.SetEnabled(true)
			runtime.SetTrustedProxies([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
			server, client := nativeProxyOptions(t, name)
			client["transport"].(map[string]any)["headers"] = map[string]any{"X-Forwarded-For": "192.0.2.99"}
			serverCore := core.NewCoreWithContext(connectionpolicy.WithGuard(context.Background(), runtime))
			runCore(t, serverCore, []any{server}, []any{map[string]any{"type": "direct", "tag": "direct"}})
			clientCore := core.NewCore()
			runCore(t, clientCore, nil, []any{client})
			outbound, _ := clientCore.GetInstance().Outbound().Outbound("access")
			echo, _ := echoServer(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			t.Cleanup(cancel)
			conn, err := outbound.DialContext(ctx, "tcp", M.ParseSocksaddr(echo))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			exchange(t, conn)
			assertReportedSource(t, runtime, "192.0.2.99")
			runtime.SetTrustedProxies(nil)
			exchange(t, conn)
			assertReportedSource(t, runtime, "127.0.0.1")
		})
	}
}

func assertReportedSource(t *testing.T, runtime *ipruntime.Runtime, address string) {
	t.Helper()
	state := runtime.Report("local").Snapshot
	if len(state.Entries) != 1 || state.Entries[0].Address != netip.MustParseAddr(address) || state.Entries[0].ActivityAge == nil {
		t.Fatalf("unexpected current source: %+v", state)
	}
}

func testNativeDatagrams(t *testing.T, name string) {
	t.Helper()
	var elapsed atomic.Int64
	runtime, err := ipruntime.New(engine.DefaultProfile(), func() time.Time { return time.Unix(0, elapsed.Load()) })
	if err != nil {
		t.Fatal(err)
	}
	runtime.SetUsers(map[ipruntime.Identity]string{{Inbound: "access", User: "user"}: "client"})
	runtime.SetEnabled(true)
	server, client := nativeProxyOptions(t, name)
	serverCore := core.NewCoreWithContext(connectionpolicy.WithGuard(context.Background(), runtime))
	runCore(t, serverCore, []any{server}, []any{map[string]any{"type": "direct", "tag": "direct"}})
	clientCore := core.NewCore()
	runCore(t, clientCore, nil, []any{client})
	outbound, _ := clientCore.GetInstance().Outbound().Outbound("access")
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	var received atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		var data [4096]byte
		for {
			n, address, err := echo.ReadFrom(data[:])
			if err != nil {
				return
			}
			received.Add(1)
			_, _ = echo.WriteTo(data[:n], address)
		}
	}()
	t.Cleanup(func() { _ = echo.Close(); <-done })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := outbound.ListenPacket(ctx, M.SocksaddrFromNet(echo.LocalAddr()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	stop := time.AfterFunc(3*time.Second, func() { _ = conn.Close() })
	defer stop.Stop()
	if _, err := conn.WriteTo([]byte{42}, echo.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	var data [65535]byte
	if n, _, err := conn.ReadFrom(data[:]); err != nil || n != 1 || data[0] != 42 {
		t.Fatal("native datagram exchange failed", err)
	}
	assertPhysicalReport(t, runtime)
	elapsed.Store(int64(61 * time.Second))
	report := runtime.Report("local")
	if err := runtime.Apply(ipruntime.Decision{Scope: "controller", Challenge: report.Challenge, Revision: 1,
		Rules: []ipruntime.Rule{{Client: "client", Limit: 1, Complete: true, Denied: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}}}); err != nil {
		t.Fatal(err)
	}
	before := received.Load()
	stop.Stop()
	stop = time.AfterFunc(300*time.Millisecond, func() { _ = conn.Close() })
	_, _ = conn.WriteTo([]byte{43}, echo.LocalAddr())
	if _, _, err := conn.ReadFrom(data[:]); err == nil {
		t.Fatal("existing datagram session bypassed denial")
	}
	stop.Stop()
	if received.Load() != before {
		t.Fatal("denied datagram reached outbound")
	}
}

func testNativeProxy(t *testing.T, name string) {
	t.Helper()
	var elapsed atomic.Int64
	runtime, err := ipruntime.New(engine.DefaultProfile(), func() time.Time { return time.Unix(0, elapsed.Load()) })
	if err != nil {
		t.Fatal(err)
	}
	runtime.SetUsers(map[ipruntime.Identity]string{{Inbound: "access", User: "user"}: "client"})
	runtime.SetEnabled(true)
	server, client := nativeProxyOptions(t, name)
	serverCore := core.NewCoreWithContext(connectionpolicy.WithGuard(context.Background(), runtime))
	runCore(t, serverCore, []any{server}, []any{map[string]any{"type": "direct", "tag": "direct"}})
	clientCore := core.NewCore()
	runCore(t, clientCore, nil, []any{client})
	outbound, ok := clientCore.GetInstance().Outbound().Outbound("access")
	if !ok {
		t.Fatal("test outbound missing")
	}
	echo, accepted := echoServer(t)
	dial := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return outbound.DialContext(ctx, "tcp", M.ParseSocksaddr(echo))
	}
	conn, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	exchange(t, conn)
	assertPhysicalReport(t, runtime)
	elapsed.Store(int64(61 * time.Second))
	report := runtime.Report("local")
	if err := runtime.Apply(ipruntime.Decision{Scope: "controller", Challenge: report.Challenge, Revision: 1,
		Rules: []ipruntime.Rule{{Client: "client", Limit: 1, Complete: true, Denied: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}}}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	stop := time.AfterFunc(2*time.Second, func() { _ = conn.Close() })
	_, _ = conn.Write([]byte{42})
	var reply [1]byte
	if _, err := io.ReadFull(conn, reply[:]); err == nil {
		t.Fatal("existing useful stream bypassed denial")
	}
	stop.Stop()
	before := accepted.Load()
	if next, err := dial(); err == nil {
		_ = next.SetDeadline(time.Now().Add(2 * time.Second))
		stop := time.AfterFunc(2*time.Second, func() { _ = next.Close() })
		_, _ = next.Write([]byte{42})
		_, err = io.ReadFull(next, reply[:])
		_ = next.Close()
		stop.Stop()
		if err == nil {
			t.Fatal("new useful stream bypassed denial")
		}
	}
	if accepted.Load() != before {
		t.Fatal("denied stream reached outbound")
	}
}

func nativeProxyOptions(t *testing.T, name string) (map[string]any, map[string]any) {
	t.Helper()
	port := unusedPort(t)
	kind := strings.Split(name, "-")[0]
	server := map[string]any{"type": kind, "tag": "access", "listen": "127.0.0.1", "listen_port": port}
	client := map[string]any{"type": kind, "tag": "access", "server": "127.0.0.1", "server_port": port}
	user := map[string]any{"name": "user"}
	server["users"] = []any{user}
	const uuid = "11111111-1111-4111-8111-111111111111"
	switch kind {
	case "vless", "vmess", "tuic":
		user["uuid"], client["uuid"] = uuid, uuid
	case "snell":
		server["version"], client["version"] = 6, 6
		server["psk"], client["psk"] = "test-only-server-key", "test-only-server-key"
		user["userkey"], client["userkey"] = "test-only-user-key", "test-only-user-key"
	case "hysteria":
		user["auth_str"], client["auth_str"] = "test-only", "test-only"
		server["up_mbps"], server["down_mbps"], client["up_mbps"], client["down_mbps"] = 100, 100, 100, 100
	case "shadowsocks":
		configureShadowsocksTest(server, client, user, name)
	}
	if kind == "trojan" || kind == "anytls" || kind == "hysteria2" || kind == "tuic" {
		user["password"], client["password"] = "test-only", "test-only"
	}
	if kind == "vmess" {
		client["security"] = "auto"
	}
	if kind == "anytls" || kind == "hysteria" || kind == "hysteria2" || kind == "tuic" || name == "vless-quic" {
		server["tls"], client["tls"] = testTLS(t)
	}
	if strings.HasPrefix(name, "vless-") {
		mode := strings.TrimPrefix(name, "vless-")
		if mode == "mux" {
			server["multiplex"] = map[string]any{"enabled": true}
			client["multiplex"] = map[string]any{"enabled": true, "protocol": "h2mux"}
		} else {
			transport := map[string]any{"type": mode}
			if mode == "grpc" {
				transport["service_name"] = "test"
			}
			server["transport"], client["transport"] = transport, transport
		}
	}
	return server, client
}

func configureShadowsocksTest(server, client, user map[string]any, name string) {
	method, password := "aes-128-gcm", "test-only"
	if name == "shadowsocks-2022" {
		method, password = "2022-blake3-aes-128-gcm", "ZmVkY2JhOTg3NjU0MzIxMA=="
		server["password"] = "MDEyMzQ1Njc4OWFiY2RlZg=="
		client["password"] = "MDEyMzQ1Njc4OWFiY2RlZg==:" + password
	} else {
		client["password"] = password
	}
	server["method"], client["method"], user["password"] = method, method, password
}

func TestShadowTLSDetourKeepsFinalClientSource(t *testing.T) {
	runtime, err := ipruntime.New(engine.DefaultProfile(), nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime.SetUsers(map[ipruntime.Identity]string{{Inbound: "access", User: "user"}: "client"})
	runtime.SetEnabled(true)
	handshake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("test")) }))
	t.Cleanup(handshake.Close)
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(handshake.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	handshakePort, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	port := unusedPort(t)
	serverCore := core.NewCoreWithContext(connectionpolicy.WithGuard(context.Background(), runtime))
	runCore(t, serverCore, []any{
		map[string]any{"type": "vless", "tag": "access", "users": []any{map[string]any{"name": "user", "uuid": "11111111-1111-4111-8111-111111111111"}}},
		map[string]any{"type": "shadowtls", "tag": "transport", "listen": "127.0.0.1", "listen_port": port,
			"version": 3, "detour": "access", "handshake": map[string]any{"server": host, "server_port": handshakePort},
			"users": []any{map[string]any{"name": "user", "password": "test-only"}}},
	}, []any{map[string]any{"type": "direct", "tag": "direct"}})
	clientCore := core.NewCore()
	runCore(t, clientCore, nil, []any{
		map[string]any{"type": "vless", "tag": "access", "server": "127.0.0.1", "server_port": port,
			"uuid": "11111111-1111-4111-8111-111111111111", "detour": "transport"},
		map[string]any{"type": "shadowtls", "tag": "transport", "server": "127.0.0.1", "server_port": port,
			"version": 3, "password": "test-only", "tls": map[string]any{"enabled": true, "insecure": true,
				"server_name": "test.example", "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}}},
	})
	outbound, _ := clientCore.GetInstance().Outbound().Outbound("access")
	echo, _ := echoServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	conn, err := outbound.DialContext(ctx, "tcp", M.ParseSocksaddr(echo))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	exchange(t, conn)
	assertPhysicalReport(t, runtime)
}
