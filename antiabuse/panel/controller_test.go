package panel

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/alireza0/s-ui/antiabuse/engine"
	ipmodel "github.com/alireza0/s-ui/antiabuse/model"
	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/database/model"
)

func localController(t *testing.T) (*Controller, *ipruntime.Runtime, *time.Time) {
	t.Helper()
	s := newStore(t)
	if err := s.db.AutoMigrate(&model.Client{}, &model.Inbound{}, &model.ClientNode{}, &model.Node{}, &model.NodeAccessState{}); err != nil {
		t.Fatal(err)
	}
	inbound := model.Inbound{Id: 1, Enable: true, Type: "socks", Tag: "local", Options: json.RawMessage(`{}`)}
	client := model.Client{Id: 1, CreatedAt: 100, Enable: true, Name: "client", Group: "group",
		Inbounds: json.RawMessage(`[1]`), Config: json.RawMessage(`{"socks":{"username":"user","password":"test-only"}}`)}
	for _, value := range []any{&inbound, &client} {
		if err := s.db.Create(value).Error; err != nil {
			t.Fatal(err)
		}
	}
	v := config(t, s)
	v.Enabled = true
	v.Groups = []ipmodel.GroupRule{{Group: "group", Limit: 1}}
	if _, err := s.SaveConfiguration(v); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	runtime, err := ipruntime.New(engine.DefaultProfile(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewController(s, runtime, nil, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	c.now, c.scope = func() time.Time { return now }, "controller"
	c.tick(context.Background())
	return c, runtime, &now
}

func nativeFlow(t *testing.T, runtime *ipruntime.Runtime, address string) *ipruntime.Flow {
	t.Helper()
	ip := netip.MustParseAddr(address)
	f, err := runtime.Open(ipruntime.Identity{Inbound: "local", User: "user"}, func() netip.Addr { return ip })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	return f
}

func TestSourcePolicyChangeRestartsConfirmation(t *testing.T) {
	c, runtime, now := localController(t)
	first, second := nativeFlow(t, runtime, "192.0.2.1"), nativeFlow(t, runtime, "192.0.2.2")
	c.tick(context.Background())
	*now = now.Add(95 * time.Second)
	first.Activity(1)
	second.Activity(1)
	c.tick(context.Background())
	*now = now.Add(15 * time.Second)
	first.Activity(1)
	second.Activity(1)
	c.tick(context.Background())
	config, err := c.Configuration()
	if err != nil {
		t.Fatal(err)
	}
	config.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if _, err := c.SaveConfiguration(config); err != nil {
		t.Fatal(err)
	}
	c.tick(context.Background())
	*now = now.Add(15 * time.Second)
	first.Activity(1)
	second.Activity(1)
	c.tick(context.Background())
	status := c.Status([]uint{1}).Clients[0]
	if status.Denied != 0 {
		t.Fatal("confirmation from an earlier source policy was reused")
	}
}

func TestControllerLocalOnlyCountsWithoutAnyNodes(t *testing.T) {
	c, runtime, _ := localController(t)
	f := nativeFlow(t, runtime, "192.0.2.1")
	f.Activity(1)
	c.tick(context.Background())
	status := c.Status([]uint{1})
	rows := status.Clients
	if !status.Enabled || len(rows) != 1 || rows[0].Limit != 1 || !rows[0].Available || rows[0].ActiveCount == nil || *rows[0].ActiveCount != 1 {
		t.Fatalf("local-only control unavailable: %+v", rows)
	}
}

func TestControllerTransitionsAndReopensPreviouslyRejectedIP(t *testing.T) {
	c, runtime, now := localController(t)
	a := nativeFlow(t, runtime, "192.0.2.1")
	a.Activity(1)
	c.tick(context.Background())
	*now = now.Add(time.Second)
	b := nativeFlow(t, runtime, "192.0.2.2")
	b.Activity(1)
	c.tick(context.Background())
	status := c.Status([]uint{1})
	rows := status.Clients
	if !rows[0].Checking || *rows[0].ActiveCount != 2 {
		t.Fatal("temporary excess hidden from count")
	}
	for _, seconds := range []int{90, 30} {
		*now = now.Add(time.Duration(seconds) * time.Second)
		a.Activity(1)
		b.Activity(1)
		c.tick(context.Background())
	}
	if b.Permit() || !a.Permit() {
		t.Fatal("confirmed excess did not preserve incumbent")
	}
	for range 5 {
		*now = now.Add(10 * time.Second)
		if b.Permit() {
			t.Fatal("occupied slot admitted a rejected retry")
		}
		c.tick(context.Background())
	}
	*now = now.Add(11 * time.Second)
	if b.Permit() {
		t.Fatal("test expected refusal before source refresh")
	}
	c.tick(context.Background())
	if !b.Permit() {
		t.Fatal("free local slot did not reopen previous rejection")
	}
}

func TestControllerDuplicateUsernameMarksBothClientsIncomplete(t *testing.T) {
	c, _, _ := localController(t)
	duplicate := model.Client{Id: 2, CreatedAt: 200, Name: "other", Group: "group", Enable: true,
		Inbounds: json.RawMessage(`[1]`), Config: json.RawMessage(`{"socks":{"username":"user","password":"other-only"}}`)}
	if err := c.store.db.Create(&duplicate).Error; err != nil {
		t.Fatal(err)
	}
	c.tick(context.Background())
	status := c.Status([]uint{1, 2})
	rows := status.Clients
	for _, row := range rows {
		if row.Available || row.ActiveCount != nil {
			t.Fatal("ambiguous authentication presented as full coverage")
		}
	}
}

func TestControllerDisabledAndStaleCountersAreNotZero(t *testing.T) {
	c, _, now := localController(t)
	*now = now.Add(15 * time.Second)
	status := c.Status([]uint{1})
	rows := status.Clients
	if rows[0].Available || rows[0].ActiveCount != nil {
		t.Fatal("old count presented as fresh")
	}
	v := config(t, c.store)
	v.Enabled = false
	if _, err := c.SaveConfiguration(v); err != nil {
		t.Fatal(err)
	}
	c.tick(context.Background())
	status = c.Status([]uint{1})
	rows = status.Clients
	if status.Enabled || rows[0].ActiveCount != nil {
		t.Fatal("disabled module still advertised current observations")
	}
}
