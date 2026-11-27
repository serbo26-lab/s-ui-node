package wire

import (
	"math"
	"net/netip"
	"testing"
)

var identity = Identity{NodeID: 1, Epoch: "epoch", AccessRevision: 1}

func header() Header {
	return Header{Version: Version, Identity: identity, Scope: "scope", ConfigRevision: 1,
		Boot: "boot", Sequence: 1, Challenge: "challenge", Complete: true, Total: 2}
}

func entry() Observation {
	zero := int64(0)
	return Observation{Client: "client", Address: netip.MustParseAddr("192.0.2.1"), ActivityAgeMillis: &zero}
}

func page(offset int) Page {
	value := Page{Header: header(), Offset: offset, Entries: []Observation{entry()}}
	if offset == 0 {
		next := 1
		value.Next = &next
	}
	return value
}

func TestAssemblyPublishesOnlyCompleteConsistentPages(t *testing.T) {
	a := NewAssembly(identity, "scope", 1)
	if err := a.Add(page(0)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Result(); err == nil {
		t.Fatal("partial source published")
	}
	if err := a.Add(page(1)); err != nil {
		t.Fatal(err)
	}
	header, entries, err := a.Result()
	if err != nil || !header.Complete || len(entries) != 2 {
		t.Fatal("complete source not assembled")
	}
	if a.Add(page(1)) == nil {
		t.Fatal("completed source accepted more pages")
	}
}

func TestChangedPageIdentityCannotBeCombined(t *testing.T) {
	for _, edit := range []func(*Page){
		func(p *Page) { p.Boot = "replacement" },
		func(p *Page) { p.Scope = "replacement" },
		func(p *Page) { p.ConfigRevision++ },
		func(p *Page) { p.Sequence++ },
		func(p *Page) { p.Identity.AccessRevision++ },
		func(p *Page) { p.Identity.NodeID++ },
		func(p *Page) { p.Challenge = "replacement" },
		func(p *Page) { p.Complete = false },
	} {
		a := NewAssembly(identity, "scope", 1)
		if err := a.Add(page(0)); err != nil {
			t.Fatal(err)
		}
		changed := page(1)
		edit(&changed)
		if a.Add(changed) == nil {
			t.Fatal("inconsistent source pages accepted")
		}
	}
}

func TestInvalidPaginationAndObservationBounds(t *testing.T) {
	for _, edit := range []func(*Page){
		func(p *Page) { p.Version++ },
		func(p *Page) { p.Offset = 1 },
		func(p *Page) { p.Total = MaxEntries + 1 },
		func(p *Page) { p.Entries = nil },
		func(p *Page) { p.Entries = []Observation{} },
		func(p *Page) { p.Next = nil },
		func(p *Page) { p.Entries[0].Address = netip.Addr{} },
		func(p *Page) { n := int64(-1); p.Entries[0].ActivityAgeMillis = &n },
		func(p *Page) { n := int64(math.MaxInt64); p.Entries[0].ActivityAgeMillis = &n },
		func(p *Page) { p.Entries[0].Incomplete = true },
	} {
		a := NewAssembly(identity, "scope", 1)
		value := page(0)
		edit(&value)
		if a.Add(value) == nil {
			t.Fatal("invalid page accepted")
		}
	}
}

func TestEmptyAndIncompleteClientSnapshotsRemainExplicit(t *testing.T) {
	for _, entries := range [][]Observation{{}, {{Client: "client", Incomplete: true}}} {
		a := NewAssembly(identity, "scope", 1)
		value := Page{Header: header(), Entries: entries}
		value.Total = len(entries)
		if err := a.Add(value); err != nil {
			t.Fatal(err)
		}
		_, actual, err := a.Result()
		if err != nil || len(actual) != len(entries) {
			t.Fatal("empty or unsupported source lost")
		}
	}
}

func TestConfigurationAndDecisionValidation(t *testing.T) {
	configuration := Configuration{Version: Version, Identity: identity, Scope: "scope", Revision: 1,
		Profile: Profile{ActivitySeconds: 60, TransitionSeconds: 120, ConfirmationSeconds: 30}, Boot: "boot", Challenge: "challenge"}
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
	configuration.Profile.TransitionSeconds = 10
	if configuration.Validate() == nil {
		t.Fatal("invalid profile accepted")
	}
	d := Decision{Version: Version, Identity: identity, Scope: "scope", ConfigRevision: 1,
		Boot: "boot", Sequence: 1, Challenge: "challenge", Revision: 1}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	d.Identity.AccessRevision = 0
	if d.Validate() == nil {
		t.Fatal("decision without access identity accepted")
	}
}
