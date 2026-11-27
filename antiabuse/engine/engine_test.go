package engine

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

var (
	addressA = netip.MustParseAddr("192.0.2.1")
	addressB = netip.MustParseAddr("192.0.2.2")
	addressC = netip.MustParseAddr("192.0.2.3")
	start    = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
)

func newEngine(t *testing.T, limit uint32, sources ...string) *Engine {
	t.Helper()
	e, err := New(DefaultProfile())
	if err != nil {
		t.Fatal(err)
	}
	e.SetPolicies(map[string]Policy{"client": {Limit: limit, Sources: sources}})
	for _, name := range sources {
		e.SetSource(name, "boot")
	}
	return e
}

func age(value time.Duration) *time.Duration { return &value }

func active(address netip.Addr) Observation {
	return Observation{Client: "client", Address: address, ActivityAge: age(0)}
}

func attempt(address netip.Addr) Observation {
	return Observation{Client: "client", Address: address, AttemptAge: age(0)}
}

func accept(t *testing.T, e *Engine, source string, sequence uint64, at time.Time, entries ...Observation) {
	t.Helper()
	if err := e.Accept(Snapshot{Source: source, Boot: "boot", Sequence: sequence,
		Complete: true, Entries: entries}, at, at); err != nil {
		t.Fatal(err)
	}
}

func contains(values []netip.Prefix, addr netip.Addr) bool {
	prefix, _ := Address(addr)
	return slices.Contains(values, prefix)
}

func TestLocalOnlyDeduplicatesAndReplacesSnapshots(t *testing.T) {
	e := newEngine(t, 1, "local")
	accept(t, e, "local", 1, start, active(addressA), active(addressA))
	r := e.Evaluate("client", start)
	if !r.Complete || r.Active != 1 || len(r.Allowed) != 1 || len(r.Denied) != 0 {
		t.Fatalf("local snapshot: %+v", r)
	}
	accept(t, e, "local", 2, start.Add(time.Second))
	if r = e.Evaluate("client", start.Add(time.Second)); !r.Complete || r.Active != 0 {
		t.Fatalf("closed source persisted: %+v", r)
	}
}

func TestSameIPAcrossSourcesAndOneSourceLeaving(t *testing.T) {
	e := newEngine(t, 1, "local", "node-a", "node-b")
	for _, source := range []string{"local", "node-a", "node-b"} {
		accept(t, e, source, 1, start, active(addressA))
	}
	accept(t, e, "node-a", 2, start)
	r := e.Evaluate("client", start)
	if !r.Complete || r.Active != 1 || len(r.Allowed) != 1 {
		t.Fatalf("shared IP: %+v", r)
	}
}

func TestNetworkTransitionDoesNotRestrictReplacement(t *testing.T) {
	e := newEngine(t, 1, "local")
	accept(t, e, "local", 1, start, active(addressA))
	e.Evaluate("client", start)
	accept(t, e, "local", 2, start.Add(time.Second), active(addressA), active(addressB))
	if r := e.Evaluate("client", start.Add(time.Second)); !r.Checking || len(r.Allowed) != 2 {
		t.Fatalf("transition not permitted: %+v", r)
	}
	// A's open tunnel is silent. Repeated snapshots keep the activity age.
	at := start.Add(62 * time.Second)
	old := active(addressA)
	old.ActivityAge = age(61 * time.Second)
	accept(t, e, "local", 3, at, old, active(addressB))
	r := e.Evaluate("client", at)
	if r.Checking || r.Active != 1 || !contains(r.Allowed, addressB) || len(r.Denied) != 0 {
		t.Fatalf("normal transition restricted: %+v", r)
	}
}

func restrictPair(t *testing.T, e *Engine) time.Time {
	t.Helper()
	accept(t, e, "local", 1, start, active(addressA))
	e.Evaluate("client", start)
	for i, seconds := range []int{1, 91, 121} {
		at := start.Add(time.Duration(seconds) * time.Second)
		accept(t, e, "local", uint64(i+2), at, active(addressA), active(addressB))
		e.Evaluate("client", at)
	}
	return start.Add(122 * time.Second)
}

func TestConfirmedRestrictionIsConditionalAndSlotReopens(t *testing.T) {
	e := newEngine(t, 1, "local")
	at := restrictPair(t, e)
	accept(t, e, "local", 5, at, active(addressA), attempt(addressB))
	r := e.Evaluate("client", at)
	if r.Active != 1 || !contains(r.Denied, addressB) || contains(r.Allowed, addressB) || r.Checking {
		t.Fatalf("denied retry received new transition: %+v", r)
	}
	// A left on its server; B does not wait for a separate IP ban timer.
	accept(t, e, "local", 6, at.Add(time.Second), attempt(addressB))
	r = e.Evaluate("client", at.Add(time.Second))
	if r.Active != 0 || !contains(r.Allowed, addressB) || len(r.Denied) != 0 {
		t.Fatalf("free slot not reusable: %+v", r)
	}
}

func TestRepeatedCachedActivityCannotConfirmRestriction(t *testing.T) {
	e := newEngine(t, 1, "local")
	accept(t, e, "local", 1, start, active(addressA), active(addressB))
	e.Evaluate("client", start)
	for seq := uint64(2); seq < 28; seq++ {
		elapsed := time.Duration(seq*5) * time.Second
		a, b := active(addressA), active(addressB)
		a.ActivityAge, b.ActivityAge = age(elapsed), age(elapsed)
		at := start.Add(elapsed)
		accept(t, e, "local", seq, at, a, b)
		if r := e.Evaluate("client", at); len(r.Denied) != 0 {
			t.Fatalf("cached traffic confirmed restriction: %+v", r)
		}
	}
}

func TestSingleTransitionBudgetAndStableIncumbent(t *testing.T) {
	e := newEngine(t, 1, "local")
	accept(t, e, "local", 1, start, active(addressB))
	e.Evaluate("client", start)
	accept(t, e, "local", 2, start.Add(time.Second), active(addressA), active(addressB), attempt(addressC))
	r := e.Evaluate("client", start.Add(time.Second))
	if len(r.Allowed) != 2 || !contains(r.Allowed, addressB) || len(r.Denied) != 1 {
		t.Fatalf("more than one transition slot: %+v", r)
	}
}

func TestIncompleteSourcesDoNotProveDeparture(t *testing.T) {
	e := newEngine(t, 1, "local", "node")
	accept(t, e, "local", 1, start, active(addressA))
	if r := e.Evaluate("client", start); r.Complete || len(r.Denied) != 0 {
		t.Fatalf("missing source accepted: %+v", r)
	}
	accept(t, e, "node", 1, start, active(addressB))
	e.Evaluate("client", start)
	at := start.Add(15 * time.Second)
	accept(t, e, "local", 2, at, active(addressA))
	r := e.Evaluate("client", at)
	if r.Complete || r.Checking || len(r.Allowed) != 0 || len(r.Denied) != 0 {
		t.Fatalf("stale source produced decision: %+v", r)
	}
}

func TestSequenceBootAndTransitValidation(t *testing.T) {
	e := newEngine(t, 1, "local")
	accept(t, e, "local", 1, start, active(addressA))
	snapshot := Snapshot{Source: "local", Boot: "boot", Sequence: 1, Complete: true}
	if e.Accept(snapshot, start, start) == nil {
		t.Fatal("duplicate sequence accepted")
	}
	snapshot.Sequence, snapshot.Boot = 2, "old-boot"
	if e.Accept(snapshot, start, start) == nil {
		t.Fatal("old boot accepted")
	}
	snapshot.Boot = "boot"
	if e.Accept(snapshot, start, start.Add(15*time.Second)) == nil {
		t.Fatal("late response accepted")
	}
	if r := e.Evaluate("client", start); r.Active != 1 {
		t.Fatal("invalid response overwrote current state")
	}
	e.SetSource("local", "new-boot")
	if r := e.Evaluate("client", start); r.Complete {
		t.Fatal("restart reused previous picture")
	}
}

func TestSourceAndPolicyRemoval(t *testing.T) {
	e := newEngine(t, 1, "local")
	accept(t, e, "local", 1, start, active(addressA))
	e.RemoveSource("local")
	if r := e.Evaluate("client", start); r.Complete {
		t.Fatal("removed source treated as complete")
	}
	e.SetPolicies(nil)
	if r := e.Evaluate("client", start); r.Complete || r.Limit != 0 {
		t.Fatalf("removed client: %+v", r)
	}
}

func TestUnlimitedAndPolicyChange(t *testing.T) {
	e := newEngine(t, 0, "local")
	accept(t, e, "local", 1, start, active(addressA), active(addressB))
	r := e.Evaluate("client", start)
	if r.Active != 2 || len(r.Allowed) != 2 || r.Checking {
		t.Fatalf("explicit unlimited: %+v", r)
	}
	e.SetPolicies(map[string]Policy{"client": {Limit: 1, Sources: []string{"local"}}})
	r = e.Evaluate("client", start)
	if !r.Checking || len(r.Denied) != 0 {
		t.Fatalf("administrative change immediately restricted: %+v", r)
	}
}

func TestAddressNormalizationAndInheritance(t *testing.T) {
	for _, item := range []struct{ address, want string }{
		{"::ffff:192.0.2.1", "192.0.2.1/32"},
		{"2001:db8:1:2::1234", "2001:db8:1:2::/64"},
		{"fe80::1%interface", "fe80::/64"},
	} {
		got, err := Address(netip.MustParseAddr(item.address))
		if err != nil || got.String() != item.want {
			t.Fatalf("normalize %s: %s, %v", item.address, got, err)
		}
	}
	for _, address := range []netip.Addr{{}, netip.IPv4Unspecified(), netip.MustParseAddr("ff02::1")} {
		if _, err := Address(address); err == nil {
			t.Fatal("invalid source accepted")
		}
	}
	groups := map[string]uint32{"group": 4}
	zero, higher, lower := uint32(0), uint32(5), uint32(2)
	if EffectiveLimit("group", nil, groups) != 4 || EffectiveLimit("group", &zero, groups) != 0 ||
		EffectiveLimit("group", &higher, groups) != 5 || EffectiveLimit("group", &lower, groups) != 2 ||
		EffectiveLimit("missing", nil, groups) != 0 {
		t.Fatal("inheritance changed explicit policy")
	}
}

func TestProfileAndSnapshotBounds(t *testing.T) {
	profile := DefaultProfile()
	profile.Freshness = profile.Activity
	if _, err := New(profile); err == nil {
		t.Fatal("invalid profile accepted")
	}
	profile = DefaultProfile()
	profile.MaxEntries = 1
	e, err := New(profile)
	if err != nil {
		t.Fatal(err)
	}
	e.SetSource("local", "boot")
	s := Snapshot{Source: "local", Boot: "boot", Sequence: 1, Complete: true,
		Entries: []Observation{active(addressA), active(addressB)}}
	if e.Accept(s, start, start) == nil {
		t.Fatal("oversized snapshot accepted")
	}
	s.Entries = []Observation{active(addressA)}
	s.Entries[0].ActivityAge = age(-time.Second)
	if e.Accept(s, start, start) == nil {
		t.Fatal("negative age accepted")
	}
}

func TestRotatingExcessAddressDoesNotReceiveNewProvisionalSlot(t *testing.T) {
	e := newEngine(t, 1, "local")
	accept(t, e, "local", 1, start, active(addressA))
	e.Evaluate("client", start)
	accept(t, e, "local", 2, start.Add(time.Second), active(addressA), active(addressB))
	e.Evaluate("client", start.Add(time.Second))
	accept(t, e, "local", 3, start.Add(2*time.Second), active(addressA), attempt(addressC))
	r := e.Evaluate("client", start.Add(2*time.Second))
	if contains(r.Allowed, addressC) || !contains(r.Denied, addressC) {
		t.Fatalf("replacement extended transition budget: %+v", r)
	}
}

func TestUnsupportedClientDoesNotPauseUnrelatedClient(t *testing.T) {
	e := newEngine(t, 1, "local")
	snapshot := Snapshot{Source: "local", Boot: "boot", Sequence: 1, Complete: true,
		IncompleteClients: []string{"other"}, Entries: []Observation{active(addressA)}}
	if err := e.Accept(snapshot, start, start); err != nil {
		t.Fatal(err)
	}
	if r := e.Evaluate("client", start); !r.Complete || r.Active != 1 {
		t.Fatalf("unrelated client paused: %+v", r)
	}
}
