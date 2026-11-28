package runtime

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/alireza0/s-ui/antiabuse/engine"
)

var ErrDenied = errors.New("IP limit reached")

type Rule struct {
	Client   string
	Limit    uint32
	Complete bool
	Allowed  []netip.Prefix
	Denied   []netip.Prefix
}

type rule struct {
	limit   uint32
	allowed map[netip.Prefix]bool
	denied  map[netip.Prefix]bool
}

type decisionTable struct {
	expires    int64
	generation uint64
	rules      map[string]rule
}

type Decision struct {
	Scope     string
	Challenge string
	Revision  uint64
	Rules     []Rule
}

// Apply cannot extend a decision beyond the locally issued challenge deadline.
func (r *Runtime) Apply(decision Decision) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.validDecision(decision) {
		return errors.New("expired IP decision")
	}
	table := &decisionTable{expires: r.deadline, rules: make(map[string]rule, len(decision.Rules))}
	seen := make(map[string]bool, len(decision.Rules))
	for _, item := range decision.Rules {
		if item.Client == "" || seen[item.Client] {
			return errors.New("invalid IP decision client")
		}
		seen[item.Client] = true
		if !item.Complete || item.Limit == 0 {
			continue
		}
		value, err := compileRule(item)
		if err != nil {
			return err
		}
		table.rules[item.Client] = value
	}
	r.revision, r.challenge, r.scope = decision.Revision, "", decision.Scope
	r.generation++
	table.generation = r.generation
	r.reservations = map[entryKey]int64{}
	r.table.Store(table)
	return nil
}

func (r *Runtime) validDecision(value Decision) bool {
	return r.enabled.Load() && value.Scope != "" && len(value.Scope) <= 128 &&
		value.Challenge != "" && value.Challenge == r.challenge && value.Revision > 0 &&
		(value.Scope != r.scope || value.Revision > r.revision) && r.stamp() < r.deadline
}

func compileRule(item Rule) (rule, error) {
	value := rule{limit: item.Limit, allowed: map[netip.Prefix]bool{}, denied: map[netip.Prefix]bool{}}
	for _, prefix := range item.Allowed {
		if !validPrefix(prefix) {
			return rule{}, errors.New("invalid allowed IP prefix")
		}
		value.allowed[prefix] = true
	}
	for _, prefix := range item.Denied {
		if !validPrefix(prefix) || value.allowed[prefix] {
			return rule{}, errors.New("invalid denied IP prefix")
		}
		value.denied[prefix] = true
	}
	return value, nil
}

func validPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || prefix != prefix.Masked() {
		return false
	}
	normal, err := engine.Address(prefix.Addr())
	return err == nil && prefix == normal
}

func (r *Runtime) permits(entry *entry, now int64) bool {
	key := entry.key
	for {
		table := r.table.Load()
		if table == nil || now >= table.expires {
			return true
		}
		value, exists := table.rules[key.client]
		if !exists || value.allowed[key.address] {
			return true
		}
		if value.denied[key.address] {
			return false
		}
		permitted, retry := r.reserveEntry(table, value, entry, now)
		if !retry {
			return permitted
		}
	}
}

func (r *Runtime) reserveEntry(table *decisionTable, value rule, entry *entry, now int64) (bool, bool) {
	// Reservations outlive their decision table: Freshness < Activity.
	if entry.reserved.Load() == table.generation {
		return true, false
	}
	permitted, retry := r.reserve(table, value, entry.key, now)
	if permitted && !retry {
		entry.reserved.Store(table.generation)
	}
	return permitted, retry
}

func (r *Runtime) reserve(table *decisionTable, value rule, key entryKey, now int64) (bool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.table.Load() != table {
		return false, true
	}
	reserved := uint64(len(value.allowed))
	for other, expires := range r.reservations {
		if now >= expires {
			delete(r.reservations, other)
			continue
		}
		if other == key {
			return true, false
		}
		if other.client == key.client && !value.allowed[other.address] {
			reserved++
		}
	}
	if reserved >= uint64(value.limit)+1 {
		return false, false
	}
	r.reservations[key] = now + int64(r.profile.Activity)
	return true, false
}

// Flow follows a logical authenticated stream. It does not own the transport.
type Flow struct {
	runtime  *Runtime
	identity Identity
	client   atomic.Pointer[string]
	source   func() netip.Addr
	current  atomic.Pointer[entry]
	mu       sync.Mutex
	key      entryKey
	closed   atomic.Bool
}

func (r *Runtime) Open(identity Identity, source func() netip.Addr) (*Flow, error) {
	flow := &Flow{runtime: r, identity: identity, source: source}
	flow.bindClient()
	if !flow.Permit() {
		flow.Close()
		return nil, ErrDenied
	}
	return flow, nil
}

func (f *Flow) resolve() *entry {
	if f.closed.Load() {
		return nil
	}
	client := f.bindClient()
	if client == nil || *client == "" {
		return nil
	}
	address := netip.Addr{}
	if f.source != nil {
		address = f.source()
	}
	prefix, _ := engine.Address(address)
	key := entryKey{client: *client, address: prefix}
	if old := f.current.Load(); old != nil && old.key == key {
		return old
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed.Load() {
		return nil
	}
	if old := f.current.Load(); old != nil && old.key == key {
		return old
	}
	if f.key.client != "" {
		f.runtime.release(f.key, f.current.Load())
	}
	f.key = key
	var next *entry
	if prefix.IsValid() {
		next = f.runtime.acquire(key)
	} else {
		f.runtime.mu.Lock()
		f.runtime.unsupported[*client]++
		f.runtime.mu.Unlock()
	}
	f.current.Store(next)
	return next
}

func (f *Flow) bindClient() *string {
	if client := f.client.Load(); client != nil {
		return client
	}
	users := f.runtime.users.Load()
	id := users.users[f.identity]
	if id == "" && !users.ready {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed.Load() {
		return nil
	}
	if f.client.Load() == nil {
		f.runtime.retainBinding(f.identity, id)
		f.client.Store(&id)
	}
	return f.client.Load()
}

func (f *Flow) Permit() bool {
	if f.closed.Load() {
		return false
	}
	if !f.runtime.enabled.Load() {
		return true
	}
	value := f.resolve()
	if value == nil {
		return true
	}
	now := f.runtime.stamp()
	latest(&value.attempt, now)
	return f.runtime.permits(value, now)
}

func (f *Flow) Activity(size int) {
	if size <= 0 || !f.runtime.enabled.Load() {
		return
	}
	if value := f.resolve(); value != nil {
		latest(&value.activity, f.runtime.stamp())
	}
}

func (f *Flow) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed.CompareAndSwap(false, true) {
		return
	}
	if f.key.client != "" {
		f.runtime.release(f.key, f.current.Load())
	}
	if client := f.client.Load(); client != nil {
		f.runtime.releaseBinding(f.identity, *client)
	}
}
