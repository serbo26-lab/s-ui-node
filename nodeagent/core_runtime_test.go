package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"

	"github.com/alireza0/s-ui/logger"
	"github.com/op/go-logging"
	"github.com/sagernet/sing-box/adapter"
)

func TestMain(m *testing.M) {
	logger.InitLogger(logging.ERROR)
	os.Exit(m.Run())
}

func TestCoreHotUsersAndFailedReplacementKeepWorkingListener(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	d := deployment(1, 0)
	var config map[string]interface{}
	if err := json.Unmarshal(d.Config, &config); err != nil {
		t.Fatal(err)
	}
	inbound := config["inbounds"].([]interface{})[0].(map[string]interface{})
	inbound["listen_port"] = port
	d.Config, _ = json.Marshal(config)
	r := NewCoreRuntime()
	m := NewManager(7, FileStore{Directory: t.TempDir()}, r)
	defer m.Close()
	if err := m.Apply(d); err != nil {
		t.Fatal(err)
	}
	box := r.core.GetInstance()
	providerContext := r.core.GetCtx()
	oldSession, peer := net.Pipe()
	defer peer.Close()
	tracked := box.SessionTracker().RoutedConnection(context.Background(), oldSession, adapter.InboundContext{Inbound: "vpn", User: "client/4"}, nil, nil)
	defer tracked.Close()
	d.Revision = 2
	d.Config = bytes.Replace(d.Config, []byte("11111111-1111-4111-8111-111111111111"), []byte("22222222-2222-4222-8222-222222222222"), 1)
	if err := m.Apply(d); err != nil {
		t.Fatal(err)
	}
	if r.core.GetInstance() != box {
		t.Fatal("user update restarted whole core")
	}
	if providerContext.Err() != nil {
		t.Fatal("hot user update canceled certificate provider")
	}
	if sessions := box.SessionTracker().Sessions(); len(sessions) != 0 {
		t.Fatal("credential rotation left the old authenticated session alive")
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	inbound["listen_port"] = busy.Addr().(*net.TCPAddr).Port
	d.Revision = 3
	d.Config, _ = json.Marshal(config)
	if err := m.Apply(d); err == nil {
		t.Fatal("occupied listener was accepted")
	}
	if !m.Status().Running || m.Status().Revision != 2 {
		t.Fatalf("rollback lost running state: %+v", m.Status())
	}
	if providerContext.Err() == nil {
		t.Fatal("retired core left asynchronous provider work running")
	}
	check, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err == nil {
		check.Close()
		t.Fatal("original listener was not restored")
	}
}
