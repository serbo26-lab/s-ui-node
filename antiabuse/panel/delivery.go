package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	ipmodel "github.com/alireza0/s-ui/antiabuse/model"
	"github.com/alireza0/s-ui/antiabuse/wire"
)

type applicationResult struct {
	work      *work
	source    string
	signature string
	err       error
}

func ruleSignature(rules []wire.Rule) string {
	body, _ := json.Marshal(rules)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func (c *Controller) isApplied(sources []string) bool {
	for _, source := range sources {
		if c.expected[source] == "" || c.applied[source] != c.expected[source] {
			return false
		}
	}
	return len(sources) > 0
}

func (c *Controller) appliedResult(result applicationResult) {
	w := c.view.Load()
	if w == nil || w != result.work || c.expected[result.source] != result.signature {
		return
	}
	if result.err != nil {
		delete(c.applied, result.source)
	} else {
		c.applied[result.source] = result.signature
	}
	c.evaluate(w)
}

func (c *Controller) recordEvents(w *work, rules map[string][]wire.Rule, view *statusView) {
	if c.lastEvent == nil {
		c.lastEvent = map[string]string{}
	}
	current := appliedRestrictions(w, rules, view)
	var events []ipmodel.Event
	for id, signature := range current {
		if old, exists := c.lastEvent[id]; exists && old != signature {
			events = append(events, admissionEvent(w, view, id, c.now()))
		}
	}
	if len(events) > 0 && c.store.db.Create(&events).Error != nil {
		log.Print("IP control: could not store admission events")
		return
	}
	for id, signature := range current {
		c.lastEvent[id] = signature
	}
	for id := range c.lastEvent {
		if _, exists := w.clients[id]; !exists {
			delete(c.lastEvent, id)
		}
	}
	if c.now().Sub(c.lastPrune) >= time.Hour {
		if c.store.PruneEvents(c.now()) == nil {
			c.lastPrune = c.now()
		}
	}
}

func appliedRestrictions(w *work, rules map[string][]wire.Rule, view *statusView) map[string]string {
	current := map[string]string{}
	for _, values := range rules {
		for _, value := range values {
			if !view.clients[w.clients[value.Client]].Applied {
				continue
			}
			denied := slices.Clone(value.Denied)
			slices.SortFunc(denied, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
			current[value.Client] = ruleSignature([]wire.Rule{{Denied: denied}})
		}
	}
	return current
}

func admissionEvent(w *work, view *statusView, key string, now time.Time) ipmodel.Event {
	_, birth, _ := strings.Cut(key, ":")
	created, _ := strconv.ParseInt(birth, 10, 64)
	return ipmodel.Event{At: now.Unix(), ClientID: w.clients[key], CreatedAt: created,
		Code: "admission_changed", Denied: uint32(view.clients[w.clients[key]].Denied)}
}
