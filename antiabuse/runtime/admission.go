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
	expires int64
	rules   map[string]rule
}

// Apply cannot extend a decision beyond the locally issued challenge deadline.
func (r *Runtime) Apply(challenge string, revision uint64, rules []Rule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.enabled.Load() || challenge == "" || challenge != r.challenge || revision <= r.revision || r.stamp() >= r.deadline {
		return errors.New("expired IP decision")
	}
	table := &decisionTable{expires: r.deadline, rules: make(map[string]rule, len(rules))}
	seen := make(map[string]bool, len(rules))
	for _, item := range rules {
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
	r.revision, r.challenge = revision, ""
	r.reservations = map[entryKey]int64{}
	r.table.Store(table)
	return nil
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

func (r *Runtime) permits(key entryKey, now int64) bool {
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
		permitted, retry := r.reserve(table, value, key, now)
		if !retry {
			return permitted
		}
	}
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
	source   func() netip.Addr
	current  atomic.Pointer[entry]
	mu       sync.Mutex
	key      entryKey
	closed   bool
}

func (r *Runtime) Open(identity Identity, source func() netip.Addr) (*Flow, error) {
	flow := &Flow{runtime: r, identity: identity, source: source}
	if !flow.Permit() {
		flow.Close()
		return nil, ErrDenied
	}
	return flow, nil
}

func (f *Flow) resolve() *entry {
	client := f.runtime.users.Load().users[f.identity]
	if client == "" {
		return nil
	}
	address := netip.Addr{}
	if f.source != nil {
		address = f.source()
	}
	prefix, _ := engine.Address(address)
	key := entryKey{client: client, address: prefix}
	if old := f.current.Load(); old != nil && old.key == key {
		return old
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
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
		f.runtime.unsupported[client]++
		f.runtime.mu.Unlock()
	}
	f.current.Store(next)
	return next
}

func (f *Flow) Permit() bool {
	if !f.runtime.enabled.Load() {
		return true
	}
	value := f.resolve()
	if value == nil {
		return true
	}
	now := f.runtime.stamp()
	latest(&value.attempt, now)
	return f.runtime.permits(value.key, now)
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
	if !f.closed && f.key.client != "" {
		f.runtime.release(f.key, f.current.Load())
	}
	f.closed = true
}
