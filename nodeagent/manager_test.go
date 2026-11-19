package nodeagent

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeRuntime struct {
	config []byte
	calls  int
	fail   bool
}

func (f *fakeRuntime) Validate(b []byte) error {
	if !json.Valid(b) {
		return errors.New("invalid JSON")
	}
	return nil
}
func (f *fakeRuntime) Apply(b []byte) error {
	if f.fail {
		return errors.New("apply failed")
	}
	f.config = bytes.Clone(b)
	f.calls++
	return nil
}
func (f *fakeRuntime) Close() error  { f.config = nil; return nil }
func (f *fakeRuntime) Running() bool { return len(f.config) != 0 }

type failingStore struct {
	Store
	fail bool
}

func (s *failingStore) Save(d Deployment) error {
	if s.fail {
		return errors.New("disk full")
	}
	return s.Store.Save(d)
}

func deployment(revision uint64, expires int64) Deployment {
	return Deployment{NodeID: 7, Revision: revision,
		Config: json.RawMessage(`{"inbounds":[{"type":"vless","tag":"vpn","listen":"127.0.0.1","listen_port":14443,"users":[{"name":"client/4","uuid":"11111111-1111-4111-8111-111111111111"}]}],"outbounds":[{"type":"direct","tag":"direct"}]}`),
		Users:  []Access{{Name: "client/4", Expires: expires}}}
}

func TestSavedConfigurationSurvivesRestartAndExpiresOffline(t *testing.T) {
	store := FileStore{Directory: t.TempDir()}
	first := &fakeRuntime{}
	m := NewManager(7, store, first)
	m.clock = func() time.Time { return time.Unix(100, 0) }
	if err := m.Apply(deployment(1, 110)); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	second := &fakeRuntime{}
	restarted := NewManager(7, store, second)
	restarted.clock = func() time.Time { return time.Unix(120, 0) }
	if err := restarted.Restore(); err != nil {
		t.Fatal(err)
	}
	if !restarted.Status().Running || restarted.Status().Revision != 1 {
		t.Fatal(restarted.Status())
	}
	if bytes.Contains(second.config, []byte("11111111")) {
		t.Fatal("expired credentials were restored")
	}
	if err := restarted.Refresh(); err != nil {
		t.Fatal(err)
	}
	if second.calls != 1 {
		t.Fatal("unchanged configuration restarted")
	}
}

func TestRevisionConflictsDoNotChangeWorkingState(t *testing.T) {
	r := &fakeRuntime{}
	m := NewManager(7, FileStore{Directory: t.TempDir()}, r)
	if err := m.Apply(deployment(2, 0)); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(deployment(2, 0)); err != nil {
		t.Fatal(err)
	}
	if r.calls != 1 {
		t.Fatal("idempotent retry reapplied runtime")
	}
	for _, d := range []Deployment{deployment(1, 0), deployment(2, 999)} {
		if err := m.Apply(d); !errors.Is(err, ErrConflict) {
			t.Fatalf("expected conflict: %v", err)
		}
	}
	d := deployment(3, 0)
	d.NodeID = 8
	if err := m.Apply(d); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if r.calls != 1 || m.Status().Revision != 2 {
		t.Fatal("conflict mutated working revision")
	}
}

func TestDiskFailureRollsBackRuntimeAndKeepsSavedRevision(t *testing.T) {
	store := &failingStore{Store: FileStore{Directory: t.TempDir()}}
	r := &fakeRuntime{}
	m := NewManager(7, store, r)
	if err := m.Apply(deployment(1, 0)); err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(r.config)
	store.fail = true
	if err := m.Apply(deployment(2, time.Now().Add(-time.Hour).Unix())); err == nil {
		t.Fatal("save succeeded")
	}
	if !bytes.Equal(before, r.config) || m.Status().Revision != 1 {
		t.Fatal("runtime was not rolled back")
	}
	d, err := store.Load()
	if err != nil || d.Revision != 1 {
		t.Fatalf("saved revision changed: %v %v", d, err)
	}
}

func TestFailedFirstSaveStopsUnsavedRuntime(t *testing.T) {
	store := &failingStore{Store: FileStore{Directory: t.TempDir()}, fail: true}
	r := &fakeRuntime{}
	m := NewManager(7, store, r)
	if err := m.Apply(deployment(1, 0)); err == nil {
		t.Fatal("save succeeded")
	}
	if m.Status().Running || m.Status().Revision != 0 {
		t.Fatal("unsaved config kept running")
	}
}

func TestRefreshRevokesUserWithoutPanelCall(t *testing.T) {
	r := &fakeRuntime{}
	m := NewManager(7, FileStore{Directory: t.TempDir()}, r)
	now := int64(100)
	m.clock = func() time.Time { return time.Unix(now, 0) }
	if err := m.Apply(deployment(1, 101)); err != nil {
		t.Fatal(err)
	}
	now = 102
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(r.config, []byte("11111111")) || !m.Status().Running {
		t.Fatal("expiry did not remove user while keeping node running")
	}
}

func TestCorruptStateFailsClosedOnRestore(t *testing.T) {
	dir := t.TempDir()
	s := FileStore{Directory: dir}
	if err := s.Save(deployment(1, 0)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "last-good.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.Replace(b, []byte(`"revision":1`), []byte(`"revision":9`), 1)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	r := &fakeRuntime{}
	m := NewManager(7, s, r)
	if err := m.Restore(); err == nil {
		t.Fatal("corrupt state accepted")
	}
	if r.Running() {
		t.Fatal("corrupt state started")
	}
}

func TestDeploymentRequiresNamespacedAccessMetadata(t *testing.T) {
	d := deployment(1, 0)
	d.Users = nil
	if err := d.Validate(); err == nil {
		t.Fatal("untracked user accepted")
	}
	d = deployment(1, 0)
	d.Users = append(d.Users, d.Users[0])
	if err := d.Validate(); err == nil {
		t.Fatal("duplicate access accepted")
	}
}

func TestExactRetryRecoversStoppedRuntimeWithoutRewritingState(t *testing.T) {
	store := &failingStore{Store: FileStore{Directory: t.TempDir()}}
	r := &fakeRuntime{}
	m := NewManager(7, store, r)
	if err := m.Apply(deployment(1, 0)); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	store.fail = true
	if err := m.Apply(deployment(1, 0)); err != nil {
		t.Fatal(err)
	}
	if !m.Status().Running || m.Status().Revision != 1 {
		t.Fatal("exact retry did not restore runtime")
	}
}
