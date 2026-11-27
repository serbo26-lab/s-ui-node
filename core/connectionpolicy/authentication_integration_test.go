package connectionpolicy_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/alireza0/s-ui/antiabuse/engine"
	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/core"
	"github.com/alireza0/s-ui/core/connectionpolicy"
	"golang.org/x/net/proxy"
)

func TestManagedProxyRevocationAndAnonymousCoreSemantics(t *testing.T) {
	for _, kind := range []string{"http", "mixed", "socks"} {
		for _, managed := range []bool{false, true} {
			t.Run(kind+"/managed="+strconv.FormatBool(managed), func(t *testing.T) {
				testManagedProxyRevocation(t, kind, managed)
			})
		}
	}
}

func testManagedProxyRevocation(t *testing.T, kind string, managed bool) {
	t.Helper()
	runtime, err := ipruntime.New(engine.DefaultProfile(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := connectionpolicy.WithGuard(context.Background(), runtime)
	if managed {
		ctx = connectionpolicy.WithManagedAuthentication(ctx)
	}
	instance := core.NewCoreWithContext(ctx)
	port := unusedPort(t)
	options := map[string]any{"type": kind, "tag": "local", "listen": "127.0.0.1", "listen_port": port}
	users := []any{map[string]any{"username": "user", "password": "test-only"}}
	options["users"] = users
	config, err := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{options},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Stop() })
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	authenticationExchange(t, kind, address, true)
	for _, step := range []struct {
		users   any
		allowed bool
	}{{nil, !managed}, {users, true}} {
		if err := instance.RemoveInbound("local"); err != nil {
			t.Fatal(err)
		}
		options["users"] = step.users
		body, err := json.Marshal(options)
		if err != nil {
			t.Fatal(err)
		}
		if err := instance.AddInbound(body); err != nil {
			t.Fatal(err)
		}
		authenticationExchange(t, kind, address, step.allowed)
	}
}

func authenticationExchange(t *testing.T, kind, address string, allowed bool) {
	t.Helper()
	if kind == "socks" {
		destination, _ := echoServer(t)
		dialer, err := proxy.SOCKS5("tcp", address, &proxy.Auth{User: "user", Password: "test-only"}, &net.Dialer{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		conn, err := dialer.Dial("tcp", destination)
		if conn != nil {
			defer conn.Close()
		}
		if (err == nil) != allowed {
			t.Fatal("SOCKS authentication did not follow the managed user list", err)
		}
		if allowed {
			exchange(t, conn)
		}
		return
	}
	echo := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write([]byte("test")) }))
	t.Cleanup(echo.Close)
	proxyURL, err := url.Parse("http://user:test-only@" + address)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	t.Cleanup(transport.CloseIdleConnections)
	response, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(echo.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if allowed && (response.StatusCode != http.StatusOK || string(body) != "test") || !allowed && response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatal("HTTP authentication did not follow the managed user list", response.StatusCode)
	}
}

func TestManagedNaiveEmptyUsersRejectBeforeNativeAuthentication(t *testing.T) {
	ctx := connectionpolicy.WithManagedAuthentication(context.Background())
	instance := core.NewCoreWithContext(ctx)
	port := unusedPort(t)
	config, err := json.Marshal(map[string]any{"log": map[string]any{"disabled": true},
		"inbounds":  []any{map[string]any{"type": "naive", "tag": "local", "listen": "127.0.0.1", "listen_port": port, "network": "tcp"}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Stop() })
	request, err := http.NewRequest(http.MethodConnect, "http://127.0.0.1:"+strconv.Itoa(int(port)), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Padding", "test")
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:test-only")))
	response, err := (&http.Client{Timeout: 2 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatal("empty managed Naive users did not reject authentication", response.StatusCode)
	}
}
