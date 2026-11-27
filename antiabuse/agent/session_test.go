package agent

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/alireza0/s-ui/antiabuse/engine"
	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/antiabuse/wire"
)

var identity = wire.Identity{NodeID: 1, Epoch: "epoch", AccessRevision: 1}

func newSession(t *testing.T) (*Session, *ipruntime.Runtime, *time.Time) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	runtime, err := ipruntime.New(engine.DefaultProfile(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	s := New(runtime, func() time.Time { return now })
	s.SetIdentity(identity)
	return s, runtime, &now
}

func configure(t *testing.T, s *Session, scope string, revision uint64) {
	t.Helper()
	page, err := s.State(identity, "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	value := wire.Configuration{Version: wire.Version, Identity: identity, Scope: scope, Revision: revision,
		Enabled: true, Boot: page.Boot, Challenge: page.Challenge,
		Profile: wire.Profile{ActivitySeconds: 60, TransitionSeconds: 120, ConfirmationSeconds: 30}}
	if err := s.Configure(value); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationRequiresCurrentBootChallengeAndAccessIdentity(t *testing.T) {
	s, _, now := newSession(t)
	page, err := s.State(identity, "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	value := wire.Configuration{Version: wire.Version, Identity: identity, Scope: "scope", Revision: 1,
		Enabled: true, Boot: page.Boot, Challenge: page.Challenge,
		Profile: wire.Profile{ActivitySeconds: 60, TransitionSeconds: 120, ConfirmationSeconds: 30}}
	*now = now.Add(15 * time.Second)
	if s.Configure(value) == nil {
		t.Fatal("expired configuration challenge accepted")
	}
	configure(t, s, "scope", 1)
	if s.Configure(value) == nil {
		t.Fatal("earlier configuration request replayed")
	}
	page, err = s.State(identity, "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	changed := identity
	changed.AccessRevision++
	s.SetIdentity(changed)
	if _, err := s.State(identity, page.Boot, page.Sequence, 0); err == nil {
		t.Fatal("old access identity still read live observation")
	}
}

func TestDecisionMatchesFrozenObservationAndCannotReplayAcrossRestore(t *testing.T) {
	s, runtime, _ := newSession(t)
	configure(t, s, "scope", 100)
	page, err := s.State(identity, "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	value := wire.Decision{Version: wire.Version, Identity: identity, Scope: "scope", ConfigRevision: 100,
		Boot: page.Boot, Sequence: page.Sequence, Challenge: page.Challenge, Revision: 100,
		Rules: []wire.Rule{{Client: "client", Limit: 1, Complete: true, Denied: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}}}}
	if err := s.Apply(value); err != nil {
		t.Fatal(err)
	}
	if s.Apply(value) == nil {
		t.Fatal("decision challenge reused")
	}
	configure(t, s, "restored", 1)
	if s.Apply(value) == nil {
		t.Fatal("old scope revived after restore")
	}
	page, err = s.State(identity, "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	value.Scope, value.ConfigRevision, value.Revision = "restored", 1, 1
	value.Boot, value.Challenge, value.Sequence = page.Boot, page.Challenge, page.Sequence
	value.Rules = nil
	if err := s.Apply(value); err != nil {
		t.Fatal("restored lower revision not accepted:", err)
	}
	if got := runtime.Report("local"); got.Scope != "restored" {
		t.Fatal("new scope not committed to runtime")
	}
}

func TestPagesRemainFrozenAndWrongContinuationIsRejected(t *testing.T) {
	s, runtime, _ := newSession(t)
	configure(t, s, "scope", 1)
	runtime.SetUsers(map[ipruntime.Identity]string{{Inbound: "in", User: "user"}: "client"})
	for index := 1; index <= wire.PageSize+1; index++ {
		addr := netip.MustParseAddr(fmt.Sprintf("2001:db8:%x::1", index))
		f, err := runtime.Open(ipruntime.Identity{Inbound: "in", User: "user"}, func() netip.Addr { return addr })
		if err != nil {
			t.Fatal(err)
		}
		f.Activity(1)
		f.Close()
	}
	first, err := s.State(identity, "", 0, 0)
	if err != nil || first.Total != wire.PageSize+1 || first.Next == nil {
		t.Fatal("source not paginated:", err)
	}
	if _, err := s.State(identity, "wrong", first.Sequence, *first.Next); err == nil {
		t.Fatal("wrong boot continued observation")
	}
	second, err := s.State(identity, first.Boot, first.Sequence, *first.Next)
	if err != nil || second.Sequence != first.Sequence || second.Next != nil || len(second.Entries) != 1 {
		t.Fatal("snapshot continuation changed or incomplete:", err)
	}
	assembly := wire.NewAssembly(identity, "scope", 1)
	if err := assembly.Add(first); err != nil {
		t.Fatal(err)
	}
	if err := assembly.Add(second); err != nil {
		t.Fatal(err)
	}
	if _, entries, err := assembly.Result(); err != nil || len(entries) != wire.PageSize+1 {
		t.Fatal("full source was not recoverable")
	}
}
