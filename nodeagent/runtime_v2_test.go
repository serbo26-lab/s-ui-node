package nodeagent

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestV2RealCoreImportsV1AndKeepsRevokeOnRestart(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	d := Deployment{NodeID: 7, Revision: 5, Users: []Access{{Name: "client/1"}}, Config: json.RawMessage(fmt.Sprintf(`{"inbounds":[{"type":"vless","tag":"vless","listen":"127.0.0.1","listen_port":%d,"users":[{"name":"client/1","uuid":"11111111-1111-4111-8111-111111111111"}]}],"outbounds":[{"type":"direct","tag":"direct"}]}`, port))}
	state := t.TempDir()
	legacy := FileStore{Directory: state}
	if err := legacy.Save(d); err != nil {
		t.Fatal(err)
	}
	runtime := NewCoreRuntimeWithState(state)
	m := NewManagerV2(7, FileStoreV2{Directory: state}, runtime)
	if err := m.Restore(legacy); err != nil {
		t.Fatal(err)
	}
	if !m.Status().Running {
		t.Fatal("actual core did not import last-good")
	}
	if !strings.Contains(string(runtime.config), "11111111") {
		t.Fatal("legacy user was not preserved")
	}
	runtime.Interrupt()
	if runtime.Running() {
		t.Fatal("canceled core reported ready")
	}
	if err := m.Refresh(); err != nil || !runtime.Running() {
		t.Fatal("interrupted startup did not recover a fresh context", err)
	}
	deny := AccessSnapshot{NodeID: 7, Epoch: m.Status().Epoch, Revision: 1, Clients: []Grant{}}
	if err := m.ApplyAccess(deny); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(runtime.config), "11111111") || !m.Status().Running {
		t.Fatal("real hot revoke failed")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	nextRuntime := NewCoreRuntimeWithState(state)
	next := NewManagerV2(7, FileStoreV2{Directory: state}, nextRuntime)
	defer next.Close()
	if err := next.Restore(legacy); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(nextRuntime.config), "11111111") || !next.Status().Running {
		t.Fatal("restart returned to legacy ACL")
	}
}

func TestV2FreshCoreStartsAfterAccessBeforeStructure(t *testing.T) {
	state := t.TempDir()
	m := NewManagerV2(7, FileStoreV2{Directory: state}, NewCoreRuntimeWithState(state))
	defer m.Close()
	if err := m.Restore(nil); err != nil {
		t.Fatal(err)
	}
	deny := AccessSnapshot{NodeID: 7, Epoch: m.Status().Epoch, Revision: 1, Clients: []Grant{}}
	if err := m.ApplyAccess(deny); err != nil {
		t.Fatal(err)
	}
	port := freeV2Port(t)
	s := Structure{NodeID: 7, Epoch: m.Status().Epoch, Revision: 1, Config: json.RawMessage(fmt.Sprintf(`{"inbounds":[{"type":"vless","tag":"vpn","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"direct","tag":"direct"}]}`, port))}
	if err := m.ApplyStructure(s); err != nil {
		t.Fatal(err)
	}
	if !m.Status().Running {
		t.Fatal("fresh core retained a canceled bootstrap context")
	}
}
