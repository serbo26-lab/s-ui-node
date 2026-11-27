package panel

import (
	"sync"
	"testing"
	"time"
)

func TestStatusScopeAndRowsUseOnePublishedSnapshot(t *testing.T) {
	c := &Controller{now: time.Now}
	first := &statusView{scope: "first", enabled: true, updated: time.Now(),
		clients: map[uint]ClientStatus{1: {ClientID: 1, Limit: 1}}}
	second := &statusView{scope: "second", enabled: true, updated: time.Now(),
		clients: map[uint]ClientStatus{1: {ClientID: 1, Limit: 2}}}
	c.status.Store(first)
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 5000 {
			c.status.Store(first)
			c.status.Store(second)
		}
	})
	defer workers.Wait()
	for range 5000 {
		status := c.Status([]uint{1})
		if len(status.Clients) != 1 || !status.Enabled {
			t.Fatal("published snapshot disappeared")
		}
		expected := uint32(1)
		if status.Scope == "second" {
			expected = 2
		}
		if status.Clients[0].Limit != expected {
			t.Fatal("response mixed scopes and rows")
		}
	}
}
