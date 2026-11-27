package runtime

import (
	"crypto/rand"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alireza0/s-ui/antiabuse/engine"
)

type Identity struct {
	Inbound string
	User    string
}

type entryKey struct {
	client  string
	address netip.Prefix
}

type entry struct {
	key      entryKey
	activity atomic.Int64
	attempt  atomic.Int64
	refs     int
}

type bindings struct{ users map[Identity]string }

type Runtime struct {
	profile engine.Profile
	now     func() time.Time
	origin  time.Time
	boot    string
	enabled atomic.Bool
	since   atomic.Int64
	users   atomic.Pointer[bindings]
	table   atomic.Pointer[decisionTable]

	mu           sync.Mutex
	entries      map[entryKey]*entry
	unsupported  map[string]int
	incomplete   map[string]bool
	reservations map[entryKey]int64
	sequence     uint64
	revision     uint64
	scope        string
	challenge    string
	deadline     int64
}

func New(profile engine.Profile, now func() time.Time) (*Runtime, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	r := &Runtime{profile: profile, now: now, origin: now(), boot: rand.Text(),
		entries: map[entryKey]*entry{}, unsupported: map[string]int{}, reservations: map[entryKey]int64{}}
	r.users.Store(&bindings{users: map[Identity]string{}})
	return r, nil
}

func (r *Runtime) stamp() int64 { return int64(r.now().Sub(r.origin)) + 1 }

func (r *Runtime) SetEnabled(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if enabled && !r.enabled.Load() {
		r.since.Store(r.stamp())
		r.table.Store(nil)
	}
	if !enabled {
		r.table.Store(nil)
		r.challenge = ""
		r.reservations = map[entryKey]int64{}
	}
	r.enabled.Store(enabled)
}

func (r *Runtime) SetUsers(users map[Identity]string) {
	copyUsers := make(map[Identity]string, len(users))
	for key, value := range users {
		if key.User != "" && value != "" {
			copyUsers[key] = value
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if maps.Equal(r.users.Load().users, copyUsers) {
		return
	}
	r.users.Store(&bindings{users: copyUsers})
	r.table.Store(nil)
	r.challenge = ""
	r.reservations = map[entryKey]int64{}
}

func (r *Runtime) SetIncomplete(ids []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	next := make(map[string]bool, len(ids))
	for _, id := range ids {
		next[id] = true
	}
	if !maps.Equal(r.incomplete, next) {
		r.incomplete = next
		r.table.Store(nil)
		r.challenge = ""
	}
}

type Report struct {
	Snapshot  engine.Snapshot
	Challenge string
	Scope     string
}

func (r *Runtime) Configure(profile engine.Profile) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.profile != profile {
		r.profile = profile
		r.table.Store(nil)
		r.challenge = ""
		r.reservations = map[entryKey]int64{}
	}
	return nil
}

// Report retains short closed flows, but never renews their last activity.
func (r *Runtime) Report(source string) Report {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.stamp()
	r.sequence++
	r.challenge, r.deadline = rand.Text(), now+int64(r.profile.Freshness)
	report := Report{Snapshot: engine.Snapshot{Source: source, Boot: r.boot,
		Sequence: r.sequence, Complete: true}, Challenge: r.challenge, Scope: r.scope}
	if !r.enabled.Load() {
		return report
	}
	for client, count := range r.unsupported {
		if count > 0 {
			report.Snapshot.IncompleteClients = append(report.Snapshot.IncompleteClients, client)
		}
	}
	for client := range r.incomplete {
		report.Snapshot.IncompleteClients = append(report.Snapshot.IncompleteClients, client)
	}
	slices.Sort(report.Snapshot.IncompleteClients)
	report.Snapshot.IncompleteClients = slices.Compact(report.Snapshot.IncompleteClients)
	for key, value := range r.entries {
		active, attempted := value.activity.Load(), value.attempt.Load()
		activity, hasActivity := r.age(now, active)
		attempt, hasAttempt := r.age(now, attempted)
		if !hasActivity && !hasAttempt {
			if value.refs == 0 {
				delete(r.entries, key)
			}
			continue
		}
		item := engine.Observation{Client: key.client, Address: key.address.Addr()}
		if hasActivity {
			item.ActivityAge = &activity
		}
		if hasAttempt {
			item.AttemptAge = &attempt
		}
		report.Snapshot.Entries = append(report.Snapshot.Entries, item)
	}
	return report
}

func (r *Runtime) age(now, stamp int64) (time.Duration, bool) {
	age := time.Duration(now - stamp)
	return age, stamp >= r.since.Load() && stamp > 0 && age >= 0 && age < r.profile.Activity
}

func latest(value *atomic.Int64, stamp int64) {
	for old := value.Load(); stamp > old; old = value.Load() {
		if value.CompareAndSwap(old, stamp) {
			return
		}
	}
}

func (r *Runtime) acquire(key entryKey) *entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	if value := r.entries[key]; value != nil {
		value.refs++
		return value
	}
	if len(r.entries) >= r.profile.MaxEntries {
		r.unsupported[key.client]++
		return nil
	}
	value := &entry{key: key, refs: 1}
	r.entries[key] = value
	return value
}

func (r *Runtime) release(key entryKey, value *entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if value != nil {
		value.refs--
	} else if r.unsupported[key.client] > 1 {
		r.unsupported[key.client]--
	} else {
		delete(r.unsupported, key.client)
	}
}
