package connectionpolicy_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alireza0/s-ui/antiabuse/engine"
	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/core"
	"github.com/alireza0/s-ui/core/connectionpolicy"
	"github.com/alireza0/s-ui/logger"
	"github.com/op/go-logging"

	"golang.org/x/net/proxy"
)

func TestMain(m *testing.M) {
	logger.InitLogger(logging.ERROR)
	os.Exit(m.Run())
}

func echoServer(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int64
	var mu sync.Mutex
	var conns []net.Conn
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			workers.Go(func() { _, _ = io.Copy(conn, conn); _ = conn.Close() })
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		mu.Lock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return listener.Addr().String(), &accepted
}

func unusedPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return uint16(port)
}

func startLocalCore(t *testing.T, runtime *ipruntime.Runtime) proxy.Dialer {
	t.Helper()
	port := unusedPort(t)
	config, err := json.Marshal(map[string]any{
		"log": map[string]any{"disabled": true},
		"inbounds": []any{map[string]any{"type": "socks", "tag": "local", "listen": "127.0.0.1", "listen_port": port,
			"users": []any{map[string]any{"username": "user", "password": "test-only"}}}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	instance := core.NewCoreWithContext(connectionpolicy.WithGuard(context.Background(), runtime))
	if err := instance.Start(config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Stop() })
	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))),
		&proxy.Auth{User: "user", Password: "test-only"}, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return dialer
}

func exchange(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := io.ReadFull(conn, data[:]); err != nil || data[0] != 42 {
		t.Fatalf("native exchange: %v, %v", data, err)
	}
}

func TestLocalCoreAdmissionWithoutNodesAndExistingCopyLoops(t *testing.T) {
	var elapsed atomic.Int64
	now := func() time.Time { return time.Unix(0, elapsed.Load()) }
	runtime, err := ipruntime.New(engine.DefaultProfile(), now)
	if err != nil {
		t.Fatal(err)
	}
	runtime.SetUsers(map[ipruntime.Identity]string{{Inbound: "local", User: "user"}: "client"})
	runtime.SetEnabled(true)
	destination, accepted := echoServer(t)
	dialer := startLocalCore(t, runtime)
	conn, err := dialer.Dial("tcp", destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	exchange(t, conn)
	if report := runtime.Report("local"); len(report.Snapshot.Entries) != 1 || report.Snapshot.Entries[0].ActivityAge == nil {
		t.Fatal("native local traffic missing from IP observations")
	}
	elapsed.Store(int64(61 * time.Second))
	peer := netip.MustParsePrefix("127.0.0.1/32")
	apply := func(revision uint64, allow bool) {
		t.Helper()
		report := runtime.Report("local")
		rule := ipruntime.Rule{Client: "client", Limit: 1, Complete: true}
		if allow {
			rule.Allowed = []netip.Prefix{peer}
		} else {
			rule.Denied = []netip.Prefix{peer}
		}
		if err := runtime.Apply(report.Challenge, revision, []ipruntime.Rule{rule}); err != nil {
			t.Fatal(err)
		}
	}
	apply(1, false)
	_, _ = conn.Write([]byte{42})
	var data [1]byte
	if _, err := conn.Read(data[:]); err == nil {
		t.Fatal("existing routed copy bypassed updated admission")
	}
	before := accepted.Load()
	if rejected, err := dialer.Dial("tcp", destination); err == nil {
		_ = rejected.Close()
		t.Fatal("new stream bypassed current denial")
	}
	if accepted.Load() != before {
		t.Fatal("denied stream reached outbound")
	}
	apply(2, true)
	replacement, err := dialer.Dial("tcp", destination)
	if err != nil {
		t.Fatal("previous denial prevented free-slot admission:", err)
	}
	t.Cleanup(func() { _ = replacement.Close() })
	exchange(t, replacement)
}
