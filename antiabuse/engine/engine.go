package engine

import (
	"errors"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"
)

type Policy struct {
	Limit   uint32
	Sources []string
}

// Observation contains ages measured by the source's monotonic clock. AttemptAge
// is separate: a denied request must not appear as successfully flowing traffic.
type Observation struct {
	Client      string
	Address     netip.Addr
	ActivityAge *time.Duration
	AttemptAge  *time.Duration
}

type Snapshot struct {
	Source            string
	Boot              string
	Sequence          uint64
	Complete          bool
	IncompleteClients []string
	Entries           []Observation
}

type Result struct {
	Limit    uint32
	Complete bool
	Active   int
	Allowed  []netip.Prefix
	Denied   []netip.Prefix
	Checking bool
}

type source struct {
	boot       string
	sequence   uint64
	received   time.Time
	complete   bool
	incomplete map[string]bool
	entries    map[key]sample
}

type key struct {
	client  string
	address netip.Prefix
}

type sample struct {
	activity time.Time
	attempt  time.Time
}

type candidate struct {
	first    time.Time
	activity time.Time
	attempt  time.Time
}

type clientState struct {
	known        map[netip.Prefix]candidate
	allowed      map[netip.Prefix]bool
	window       time.Time
	witnesses    map[netip.Prefix]time.Time
	confirmation map[netip.Prefix]time.Time
	restricted   bool
	provisional  netip.Prefix
}

// Engine is owned by the coordinator. It performs no I/O and is never called
// for each forwarded packet. A full snapshot replaces one source's old picture.
type Engine struct {
	mu       sync.Mutex
	profile  Profile
	policies map[string]Policy
	sources  map[string]*source
	clients  map[string]*clientState
}

func New(profile Profile) (*Engine, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	return &Engine{profile: profile, policies: map[string]Policy{},
		sources: map[string]*source{}, clients: map[string]*clientState{}}, nil
}

func (e *Engine) SetPolicies(policies map[string]Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	current := make(map[string]Policy, len(policies))
	for id, policy := range policies {
		policy.Sources = slices.Clone(policy.Sources)
		slices.Sort(policy.Sources)
		policy.Sources = slices.Compact(policy.Sources)
		current[id] = policy
		old, exists := e.policies[id]
		if !exists || old.Limit != policy.Limit || !slices.Equal(old.Sources, policy.Sources) {
			delete(e.clients, id)
		}
	}
	for id := range e.clients {
		if _, exists := current[id]; !exists {
			delete(e.clients, id)
		}
	}
	e.policies = current
}

// SetSource is called only after the transport authenticates the current boot.
// A late snapshot cannot switch a source back to a previous process by itself.
func (e *Engine) SetSource(id, boot string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if old := e.sources[id]; old != nil && old.boot == boot {
		return
	}
	e.sources[id] = &source{boot: boot}
}

func (e *Engine) RemoveSource(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.sources, id)
}

// Accept uses the request start as its conservative observation time. Response
// transit cannot make old activity look newer. Invalid snapshots change nothing.
func (e *Engine) Accept(snapshot Snapshot, requested, received time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.sources[snapshot.Source]
	if s == nil || s.boot == "" || snapshot.Boot != s.boot || snapshot.Sequence == 0 || snapshot.Sequence <= s.sequence {
		return errors.New("unrecognized IP observation sequence")
	}
	if requested.IsZero() || received.Before(requested) || received.Sub(requested) >= e.profile.Freshness {
		return errors.New("expired IP observation response")
	}
	if len(snapshot.Entries) > e.profile.MaxEntries || len(snapshot.IncompleteClients) > e.profile.MaxEntries {
		return errors.New("IP observation limit exceeded")
	}
	entries, incomplete, err := parseSnapshot(snapshot, requested)
	if err != nil {
		return err
	}
	s.sequence, s.received, s.complete, s.entries = snapshot.Sequence, requested, snapshot.Complete, entries
	s.incomplete = incomplete
	return nil
}

func parseSnapshot(snapshot Snapshot, requested time.Time) (map[key]sample, map[string]bool, error) {
	entries := make(map[key]sample, len(snapshot.Entries))
	incomplete := make(map[string]bool, len(snapshot.IncompleteClients))
	for _, id := range snapshot.IncompleteClients {
		if id == "" {
			return nil, nil, errors.New("invalid incomplete IP observation client")
		}
		incomplete[id] = true
	}
	for _, entry := range snapshot.Entries {
		address, err := Address(entry.Address)
		if err != nil || entry.Client == "" || !validAge(entry.ActivityAge) || !validAge(entry.AttemptAge) {
			return nil, nil, errors.New("invalid IP observation")
		}
		if entry.ActivityAge == nil && entry.AttemptAge == nil {
			continue
		}
		k := key{entry.Client, address}
		v := entries[k]
		if entry.ActivityAge != nil {
			v.activity = later(v.activity, requested.Add(-*entry.ActivityAge))
		}
		if entry.AttemptAge != nil {
			v.attempt = later(v.attempt, requested.Add(-*entry.AttemptAge))
		}
		entries[k] = v
	}
	return entries, incomplete, nil
}

func validAge(age *time.Duration) bool { return age == nil || *age >= 0 }

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func recent(at, now time.Time, age time.Duration) bool {
	return !at.IsZero() && !at.After(now) && now.Sub(at) < age
}

func (e *Engine) Evaluate(id string, now time.Time) Result {
	e.mu.Lock()
	defer e.mu.Unlock()
	policy, exists := e.policies[id]
	result := Result{Limit: policy.Limit}
	if !exists || len(policy.Sources) == 0 {
		return result
	}
	current, complete := e.observations(id, policy.Sources, now)
	result.Complete = complete
	for _, value := range current {
		if recent(value.activity, now, e.profile.Activity) {
			result.Active++
		}
	}
	if !complete {
		// Missing data is not a normal interval or proof that an old IP left.
		delete(e.clients, id)
		return result
	}
	state := e.updateClient(id, current, now)
	addresses := sortedCandidates(state.known)
	limit := min(int(policy.Limit), len(addresses))
	if policy.Limit == 0 {
		limit = len(addresses)
	}
	keep := retainAllowed(state.allowed, addresses, limit)
	if len(addresses) <= limit {
		state.window = time.Time{}
		state.witnesses, state.confirmation = nil, nil
		state.restricted = false
		state.provisional = netip.Prefix{}
		state.allowed = keep
		result.Allowed = prefixKeys(keep)
		return result
	}
	confirmed := e.transition(state, addresses, keep, now)
	return finishDecision(state, addresses, keep, limit, confirmed, result)
}

func (e *Engine) transition(state *clientState, addresses []netip.Prefix, keep map[netip.Prefix]bool, now time.Time) bool {
	if state.window.IsZero() {
		state.window = now
		state.witnesses = activityTimes(state.known)
		for _, addr := range addresses {
			if !keep[addr] {
				state.provisional = addr
				break
			}
		}
	}
	elapsed := now.Sub(state.window)
	if elapsed >= e.profile.Transition-e.profile.Confirmation && state.confirmation == nil {
		state.confirmation = activityTimes(state.known)
	}
	confirmed := state.restricted || elapsed >= e.profile.Transition && e.confirmed(state)
	state.restricted = confirmed
	return confirmed
}

func finishDecision(state *clientState, addresses []netip.Prefix, keep map[netip.Prefix]bool, limit int, confirmed bool, result Result) Result {
	result.Checking = !confirmed
	for _, address := range addresses {
		if keep[address] {
			continue
		}
		if !confirmed && address == state.provisional {
			// One provisional address per incident; retries do not restart it.
			keep[address] = true
			continue
		}
		result.Denied = append(result.Denied, address)
	}
	state.allowed = retainAllowed(state.allowed, addresses, limit)
	result.Allowed = prefixKeys(keep)
	return result
}

func (e *Engine) observations(id string, sources []string, now time.Time) (map[netip.Prefix]sample, bool) {
	current := map[netip.Prefix]sample{}
	complete := true
	for _, name := range sources {
		s := e.sources[name]
		if s == nil || !s.complete || !recent(s.received, now, e.profile.Freshness) {
			complete = false
			continue
		}
		if s.incomplete[id] {
			complete = false
		}
		for k, value := range s.entries {
			if k.client != id || (!recent(value.activity, now, e.profile.Activity) && !recent(value.attempt, now, e.profile.Activity)) {
				continue
			}
			old := current[k.address]
			old.activity = later(old.activity, value.activity)
			old.attempt = later(old.attempt, value.attempt)
			current[k.address] = old
		}
	}
	return current, complete
}

func (e *Engine) updateClient(id string, current map[netip.Prefix]sample, now time.Time) *clientState {
	state := e.clients[id]
	if state == nil {
		state = &clientState{known: map[netip.Prefix]candidate{}, allowed: map[netip.Prefix]bool{}}
		e.clients[id] = state
	}
	for addr := range state.known {
		if _, ok := current[addr]; !ok {
			delete(state.known, addr)
			delete(state.allowed, addr)
		}
	}
	for addr, value := range current {
		old, exists := state.known[addr]
		if !exists {
			old.first = now
		}
		old.activity, old.attempt = value.activity, value.attempt
		state.known[addr] = old
	}
	return state
}

func (e *Engine) confirmed(state *clientState) bool {
	if state.confirmation == nil {
		return false
	}
	count := 0
	for addr, candidate := range state.known {
		initial, started := state.witnesses[addr]
		final, checked := state.confirmation[addr]
		if started && checked && final.After(initial) && candidate.activity.After(final) {
			count++
		}
	}
	// An incident can be confirmed only by fresh traffic from more than the
	// number of retained slots; repeated denied attempts are not traffic.
	return count > len(state.allowed)
}

func sortedCandidates(values map[netip.Prefix]candidate) []netip.Prefix {
	keys := slices.Collect(maps.Keys(values))
	slices.SortFunc(keys, func(a, b netip.Prefix) int {
		if v := values[a].first.Compare(values[b].first); v != 0 {
			return v
		}
		return a.Addr().Compare(b.Addr())
	})
	return keys
}

func activityTimes(values map[netip.Prefix]candidate) map[netip.Prefix]time.Time {
	result := make(map[netip.Prefix]time.Time, len(values))
	for addr, value := range values {
		result[addr] = value.activity
	}
	return result
}

func retainAllowed(old map[netip.Prefix]bool, addresses []netip.Prefix, limit int) map[netip.Prefix]bool {
	keep := map[netip.Prefix]bool{}
	for _, addr := range addresses {
		if old[addr] && len(keep) < limit {
			keep[addr] = true
		}
	}
	for _, addr := range addresses {
		if len(keep) >= limit {
			break
		}
		keep[addr] = true
	}
	return keep
}

func prefixKeys(values map[netip.Prefix]bool) []netip.Prefix {
	keys := slices.Collect(maps.Keys(values))
	slices.SortFunc(keys, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return keys
}
