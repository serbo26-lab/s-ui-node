package runtime

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alireza0/s-ui/antiabuse/engine"
)

var sourceA = netip.MustParseAddr("192.0.2.1")
var sourceB = netip.MustParseAddr("192.0.2.2")

type clock struct{ elapsed atomic.Int64 }

func (c *clock) now() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(c.elapsed.Load()))
}

func (c *clock) advance(d time.Duration) { c.elapsed.Add(int64(d)) }

func newRuntime(t *testing.T) (*Runtime, *clock) {
	t.Helper()
	c := &clock{}
	r, err := New(engine.DefaultProfile(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	r.SetUsers(map[Identity]string{{Inbound: "in", User: "user"}: "client"})
	r.SetEnabled(true)
	return r, c
}

func openFlow(t *testing.T, r *Runtime, source netip.Addr) *Flow {
	t.Helper()
	f, err := r.Open(Identity{Inbound: "in", User: "user"}, func() netip.Addr { return source })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	return f
}

func prefix(addr netip.Addr) netip.Prefix {
	p, _ := engine.Address(addr)
	return p
}

func decision(t *testing.T, r *Runtime, revision uint64, allowed, denied []netip.Prefix) {
	t.Helper()
	report := r.Report("local")
	if err := r.Apply(Decision{Scope: "controller", Challenge: report.Challenge, Revision: revision, Rules: []Rule{{Client: "client", Limit: 1,
		Complete: true, Allowed: allowed, Denied: denied}}}); err != nil {
		t.Fatal(err)
	}
}

func TestBackgroundFlowDoesNotCreateActivityAndRemainsReusable(t *testing.T) {
	r, c := newRuntime(t)
	f := openFlow(t, r, sourceA)
	report := r.Report("local")
	if len(report.Snapshot.Entries) != 1 || report.Snapshot.Entries[0].ActivityAge != nil {
		t.Fatal("opening a tunnel was counted as useful traffic")
	}
	c.advance(61 * time.Second)
	if len(r.Report("local").Snapshot.Entries) != 0 {
		t.Fatal("silent tunnel occupied a slot indefinitely")
	}
	if !f.Permit() {
		t.Fatal("idle flow could not resume")
	}
	f.Activity(1)
	if report = r.Report("local"); len(report.Snapshot.Entries) != 1 || report.Snapshot.Entries[0].ActivityAge == nil {
		t.Fatal("resumed flow was not observed")
	}
}

func TestExistingFlowCannotBypassNewDecisionAfterIdle(t *testing.T) {
	r, c := newRuntime(t)
	f := openFlow(t, r, sourceB)
	f.Activity(1)
	c.advance(61 * time.Second)
	decision(t, r, 1, []netip.Prefix{prefix(sourceA)}, []netip.Prefix{prefix(sourceB)})
	if f.Permit() {
		t.Fatal("old flow bypassed updated admission")
	}
	report := r.Report("local")
	if len(report.Snapshot.Entries) != 1 || report.Snapshot.Entries[0].ActivityAge != nil {
		t.Fatal("denied retry was counted as active traffic")
	}
	decision(t, r, 2, []netip.Prefix{prefix(sourceB)}, nil)
	if !f.Permit() {
		t.Fatal("previous rejection survived a free slot")
	}
}

func TestObservationUpdatesFromLongFlowAndRetainsClosedShortFlow(t *testing.T) {
	r, c := newRuntime(t)
	f := openFlow(t, r, sourceA)
	for range 10 {
		c.advance(20 * time.Second)
		f.Activity(1)
	}
	f.Close()
	c.advance(5 * time.Second)
	report := r.Report("local")
	if len(report.Snapshot.Entries) != 1 || *report.Snapshot.Entries[0].ActivityAge != 5*time.Second {
		t.Fatalf("closed flow lost or refreshed: %+v", report.Snapshot)
	}
	c.advance(time.Minute)
	if len(r.Report("local").Snapshot.Entries) != 0 {
		t.Fatal("closed old activity retained as fresh")
	}
}

func TestDelayedReplayedAndExpiredDecisions(t *testing.T) {
	r, c := newRuntime(t)
	report := r.Report("local")
	c.advance(14 * time.Second)
	rules := []Rule{{Client: "client", Complete: true, Limit: 1, Denied: []netip.Prefix{prefix(sourceB)}}}
	if err := r.Apply(Decision{Scope: "controller", Challenge: report.Challenge, Revision: 1, Rules: rules}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Open(Identity{Inbound: "in", User: "user"}, func() netip.Addr { return sourceB }); !errors.Is(err, ErrDenied) {
		t.Fatal("current denial not applied")
	}
	c.advance(time.Second)
	// Expiration is measured from the challenge, not receipt of this decision.
	f := openFlow(t, r, sourceB)
	f.Close()
	if r.Apply(Decision{Scope: "controller", Challenge: report.Challenge, Revision: 2, Rules: rules}) == nil {
		t.Fatal("replay renewed decision")
	}
	report = r.Report("local")
	c.advance(15 * time.Second)
	if r.Apply(Decision{Scope: "controller", Challenge: report.Challenge, Revision: 2, Rules: rules}) == nil {
		t.Fatal("expired challenge accepted")
	}
}

func TestNewChallengeAndDisableInvalidateOldDecision(t *testing.T) {
	r, c := newRuntime(t)
	old := r.Report("local")
	r.Report("local")
	if r.Apply(Decision{Scope: "controller", Challenge: old.Challenge, Revision: 1, Rules: nil}) == nil {
		t.Fatal("previous challenge accepted")
	}
	f := openFlow(t, r, sourceA)
	f.Activity(1)
	r.SetEnabled(false)
	c.advance(time.Second)
	f.Activity(1)
	if len(r.Report("local").Snapshot.Entries) != 0 {
		t.Fatal("disabled collector still collecting")
	}
	r.SetEnabled(true)
	if len(r.Report("local").Snapshot.Entries) != 0 {
		t.Fatal("old activity became fresh on re-enable")
	}
	f.Activity(1)
	if len(r.Report("local").Snapshot.Entries) != 1 {
		t.Fatal("existing flow did not observe enable")
	}
}

func TestInvalidSourceMarksOnlyAffectedClientIncomplete(t *testing.T) {
	r, _ := newRuntime(t)
	f := openFlow(t, r, netip.Addr{})
	report := r.Report("local")
	if !report.Snapshot.Complete || len(report.Snapshot.IncompleteClients) != 1 || report.Snapshot.IncompleteClients[0] != "client" {
		t.Fatal("unknown source hidden or affected entire server")
	}
	f.Close()
	if len(r.Report("local").Snapshot.IncompleteClients) != 0 {
		t.Fatal("closed unsupported flow remained")
	}
}

func TestSharedIPConcurrentFlowsAndImmutableBindings(t *testing.T) {
	r, _ := newRuntime(t)
	users := map[Identity]string{{Inbound: "in", User: "user"}: "client"}
	r.SetUsers(users)
	users[Identity{Inbound: "in", User: "user"}] = "changed"
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			f, err := r.Open(Identity{Inbound: "in", User: "user"}, func() netip.Addr { return sourceA })
			if err != nil {
				t.Error(err)
				return
			}
			defer f.Close()
			for range 100 {
				if f.Permit() {
					f.Activity(1)
				}
			}
		})
	}
	wg.Wait()
	report := r.Report("local")
	if len(report.Snapshot.Entries) != 1 || report.Snapshot.Entries[0].Client != "client" {
		t.Fatal("flow count or external mutation changed stable identity")
	}
}

func TestLocalUnknownAdmissionBound(t *testing.T) {
	r, _ := newRuntime(t)
	decision(t, r, 1, []netip.Prefix{prefix(sourceA)}, nil)
	f := openFlow(t, r, sourceB)
	f.Activity(1)
	_, err := r.Open(Identity{Inbound: "in", User: "user"}, func() netip.Addr { return netip.MustParseAddr("192.0.2.3") })
	if !errors.Is(err, ErrDenied) {
		t.Fatal("unbounded provisional addresses")
	}
}

func TestMalformedRuleDoesNotReplaceLiveTable(t *testing.T) {
	r, _ := newRuntime(t)
	decision(t, r, 1, nil, []netip.Prefix{prefix(sourceB)})
	report := r.Report("local")
	invalid := []Rule{{Client: "client", Limit: 1, Complete: true, Allowed: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}}}
	if r.Apply(Decision{Scope: "controller", Challenge: report.Challenge, Revision: 2, Rules: invalid}) == nil {
		t.Fatal("invalid normalized prefix accepted")
	}
	_, err := r.Open(Identity{Inbound: "in", User: "user"}, func() netip.Addr { return sourceB })
	if !errors.Is(err, ErrDenied) {
		t.Fatal("malformed decision replaced current one")
	}
}

func TestNewControllerScopeAcceptsLowerRevisionWithoutReplayingOldAnswer(t *testing.T) {
	r, _ := newRuntime(t)
	decision(t, r, 100, nil, []netip.Prefix{prefix(sourceB)})
	old := r.Report("local")
	current := r.Report("local")
	value := Decision{Scope: "replacement", Challenge: current.Challenge, Revision: 1,
		Rules: []Rule{{Client: "client", Limit: 1, Complete: true, Allowed: []netip.Prefix{prefix(sourceB)}}}}
	if err := r.Apply(value); err != nil {
		t.Fatal("new control scope rejected restored lower revision:", err)
	}
	value.Scope, value.Challenge, value.Revision = "controller", old.Challenge, 101
	if r.Apply(value) == nil {
		t.Fatal("delayed old scope renewed decision")
	}
	if report := r.Report("local"); report.Scope != "replacement" {
		t.Fatal("accepted control scope not reported")
	}
	f := openFlow(t, r, sourceB)
	if !f.Permit() {
		t.Fatal("old restriction survived new scope")
	}
}

func TestProfileChangeDoesNotNeedCoreRestartOrAcceptOldChallenge(t *testing.T) {
	r, _ := newRuntime(t)
	decision(t, r, 1, nil, []netip.Prefix{prefix(sourceB)})
	old := r.Report("local")
	profile := engine.DefaultProfile()
	profile.Activity = 90 * time.Second
	if err := r.Configure(profile); err != nil {
		t.Fatal(err)
	}
	value := Decision{Scope: "controller", Challenge: old.Challenge, Revision: 2}
	if r.Apply(value) == nil {
		t.Fatal("old profile challenge applied")
	}
	f := openFlow(t, r, sourceB)
	if !f.Permit() {
		t.Fatal("old table survived configuration change")
	}
}

func TestReusedUsernameDoesNotReassignAnExistingFlow(t *testing.T) {
	r, _ := newRuntime(t)
	old := openFlow(t, r, sourceA)
	r.SetUsers(map[Identity]string{{Inbound: "in", User: "user"}: "replacement"})
	old.Activity(1)
	current := openFlow(t, r, sourceA)
	current.Activity(1)
	report := r.Report("local")
	seen := map[string]bool{}
	for _, value := range report.Snapshot.Entries {
		if value.ActivityAge != nil {
			seen[value.Client] = true
		}
	}
	if !seen["client"] || !seen["replacement"] || len(seen) != 2 {
		t.Fatal("username reuse transferred a live flow to another client")
	}
}
