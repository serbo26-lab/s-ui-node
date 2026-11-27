//go:build with_quic

package connectionpolicy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/alireza0/s-ui/antiabuse/engine"
	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/core"
	"github.com/alireza0/s-ui/core/connectionpolicy"
	M "github.com/sagernet/sing/common/metadata"
)

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

func testNativeProxy(t *testing.T, name string) {
	t.Helper()
	var elapsed atomic.Int64
	runtime, err := ipruntime.New(engine.DefaultProfile(), func() time.Time { return time.Unix(0, elapsed.Load()) })
	if err != nil {
		t.Fatal(err)
	}
	runtime.SetUsers(map[ipruntime.Identity]string{{Inbound: "access", User: "user"}: "client"})
	runtime.SetEnabled(true)
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
		user["psk"], client["psk"] = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	case "hysteria":
		user["auth_str"], client["auth_str"] = "test-only", "test-only"
		server["up_mbps"], server["down_mbps"], client["up_mbps"], client["down_mbps"] = 100, 100, 100, 100
	case "shadowsocks":
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
	_, _ = conn.Write([]byte{42})
	var reply [1]byte
	if _, err := io.ReadFull(conn, reply[:]); err == nil {
		t.Fatal("existing useful stream bypassed denial")
	}
	before := accepted.Load()
	if next, err := dial(); err == nil {
		_ = next.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = next.Write([]byte{42})
		_, err = io.ReadFull(next, reply[:])
		_ = next.Close()
		if err == nil {
			t.Fatal("new useful stream bypassed denial")
		}
	}
	if accepted.Load() != before {
		t.Fatal("denied stream reached outbound")
	}
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
