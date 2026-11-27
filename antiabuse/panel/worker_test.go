package panel

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alireza0/s-ui/database/model"
)

type stalledTransport struct{ entered chan struct{} }

func (t stalledTransport) Open(ctx context.Context, _ model.Node) (Peer, error) {
	select {
	case t.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestStalledNodeDoesNotHoldLocalControlOrUnrelatedClient(t *testing.T) {
	c, runtime, _ := localController(t)
	for _, row := range []any{
		&model.Node{Id: 1, Enable: true, ControlEpoch: "epoch"},
		&model.NodeAccessState{NodeId: 1, DesiredRevision: 1, AppliedRevision: 1},
		&model.Client{Id: 2, CreatedAt: 200, Enable: true, Name: "remote", Group: "group",
			Config: json.RawMessage(`{}`), Inbounds: json.RawMessage(`[]`)},
		&model.ClientNode{ClientId: 2, NodeId: 1, Active: true},
	} {
		if err := c.store.db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	entered := make(chan struct{}, 1)
	c.transport = stalledTransport{entered: entered}
	stop := c.Start(context.Background())
	defer stop()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("node worker did not start")
	}
	f := nativeFlow(t, runtime, "192.0.2.1")
	f.Activity(1)
	c.Notify()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("local observation waited for the stalled node")
		case <-ticker.C:
			status := c.Status([]uint{1, 2})
			rows := status.Clients
			if len(rows) != 2 || rows[0].ActiveCount == nil {
				continue
			}
			if *rows[0].ActiveCount == 1 && rows[0].Applied {
				if rows[1].Available || rows[1].Applied {
					t.Fatal("missing node treated as complete")
				}
				return
			}
		}
	}
}

func TestDisabledModuleRetainsEffectivePolicyWithoutCollecting(t *testing.T) {
	c, runtime, _ := localController(t)
	value := config(t, c.store)
	value.Enabled = false
	if _, err := c.SaveConfiguration(value); err != nil {
		t.Fatal(err)
	}
	c.tick(context.Background())
	status := c.Status([]uint{1})
	rows := status.Clients
	if status.Enabled || rows[0].Limit != 1 || rows[0].LimitSource != "group" || rows[0].ActiveCount != nil {
		t.Fatal("disabled control lost the effective policy or advertised fresh data")
	}
	f := nativeFlow(t, runtime, "192.0.2.1")
	f.Activity(1)
	if report := runtime.Report("local"); len(report.Snapshot.Entries) != 0 {
		t.Fatal("disabled runtime collected activity")
	}
}
