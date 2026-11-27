package connectionpolicy_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/alireza0/s-ui/antiabuse/engine"
	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/core"
	"github.com/alireza0/s-ui/core/connectionpolicy"
)

func TestHTTPAndMixedProxyKeepPhysicalPeerAcrossInternalPipes(t *testing.T) {
	for _, kind := range []string{"http", "mixed"} {
		t.Run(kind, func(t *testing.T) {
			runtime, address := startProxyCore(t, kind)
			echo := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write([]byte("response")) }))
			t.Cleanup(echo.Close)
			proxyURL, err := url.Parse("http://user:test-only@" + address)
			if err != nil {
				t.Fatal(err)
			}
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			for _, spoofed := range []string{"192.0.2.1", "192.0.2.2"} {
				request, err := http.NewRequest(http.MethodGet, echo.URL, nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("X-Forwarded-For", spoofed)
				request.Header.Set("X-Real-IP", spoofed)
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != http.StatusOK || string(body) != "response" {
					t.Fatal("native HTTP proxy exchange failed")
				}
			}
			assertPhysicalReport(t, runtime)
		})
	}
}

func startProxyCore(t *testing.T, kind string) (*ipruntime.Runtime, string) {
	t.Helper()
	runtime, err := ipruntime.New(engine.DefaultProfile(), nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime.SetUsers(map[ipruntime.Identity]string{{Inbound: "local", User: "user"}: "client"})
	runtime.SetEnabled(true)
	port := unusedPort(t)
	options := map[string]any{"type": kind, "tag": "local", "listen": "127.0.0.1", "listen_port": port,
		"users": []any{map[string]any{"username": "user", "password": "test-only"}}}
	if kind == "naive" {
		options["network"] = "tcp"
	}
	config, err := json.Marshal(map[string]any{"log": map[string]any{"disabled": true},
		"inbounds": []any{options}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}})
	if err != nil {
		t.Fatal(err)
	}
	instance := core.NewCoreWithContext(connectionpolicy.WithGuard(context.Background(), runtime))
	if err := instance.Start(config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Stop() })
	return runtime, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
}

func TestMixedSOCKSRetainsAuthenticationAndSource(t *testing.T) {
	runtime, address := startProxyCore(t, "mixed")
	echo, _ := echoServer(t)
	dialer, err := proxy.SOCKS5("tcp", address, &proxy.Auth{User: "user", Password: "test-only"}, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.Dial("tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	var reply [1]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply[0] != 42 {
		t.Fatal("mixed SOCKS payload failed", err)
	}
	assertPhysicalReport(t, runtime)
}

func assertPhysicalReport(t *testing.T, runtime *ipruntime.Runtime) {
	t.Helper()
	report := runtime.Report("local").Snapshot
	if !report.Complete || len(report.IncompleteClients) != 0 || len(report.Entries) != 1 ||
		report.Entries[0].Address != netip.MustParseAddr("127.0.0.1") || report.Entries[0].ActivityAge == nil {
		t.Fatalf("proxy trusted forwarded metadata or lost the physical client: %+v", report)
	}
}
