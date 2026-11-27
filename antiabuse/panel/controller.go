package panel

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alireza0/s-ui/antiabuse/engine"
	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/antiabuse/wire"
	"github.com/alireza0/s-ui/database/model"
)

type Peer interface {
	Observe(context.Context, wire.Configuration) (wire.Header, []wire.Observation, time.Time, error)
	Apply(context.Context, wire.Decision) error
	Close()
}

type Transport interface {
	Open(context.Context, model.Node) (Peer, error)
}

type ClientStatus struct {
	LimitSource       string `json:"limit_source"`
	RequestedRevision uint64 `json:"requested_revision"`
	AppliedRevision   uint64 `json:"applied_revision"`
	ClientID          uint   `json:"client_id"`
	Limit             uint32 `json:"limit"`
	Available         bool   `json:"available"`
	ActiveCount       *int   `json:"active_count"`
	Checking          bool   `json:"checking"`
	UpdatedAt         int64  `json:"updated_at"`
	Denied            int    `json:"denied"`
	Applied           bool   `json:"applied"`
}

type work struct {
	revision     uint64
	limitSources map[string]string
	key          string
	scope        string
	config       Configuration
	policies     map[string]engine.Policy
	clients      map[string]uint
	targets      map[string]target
}

type target struct {
	node     model.Node
	identity wire.Identity
}

type observationResult struct {
	work      *work
	source    string
	header    wire.Header
	entries   []wire.Observation
	requested time.Time
	err       error
	answer    chan *wire.Decision
}

type statusView struct {
	enabled bool
	updated time.Time
	clients map[uint]ClientStatus
}

// Controller's engine and worker lifecycle have one owner. Remote I/O runs
// independently; a stalled peer cannot hold the local sampling loop.
type Controller struct {
	store          *Store
	now            func() time.Time
	local          *ipruntime.Runtime
	ready          func() bool
	transport      Transport
	view           atomic.Pointer[work]
	status         atomic.Pointer[statusView]
	dirty          atomic.Bool
	wake           chan struct{}
	results        chan observationResult
	acks           chan applicationResult
	slots          chan struct{}
	engine         *engine.Engine
	profile        engine.Profile
	scope          string
	revision       uint64
	policyRevision uint64
	workers        map[string]context.CancelFunc
	wg             sync.WaitGroup
	applied        map[string]string
	expected       map[string]string
	lastEvent      map[string]string
	lastPrune      time.Time
}

func NewController(store *Store, local *ipruntime.Runtime, transport Transport, ready func() bool) (*Controller, error) {
	if err := store.Initialize(); err != nil {
		return nil, err
	}
	return &Controller{store: store, now: time.Now, local: local, transport: transport, ready: ready,
		wake: make(chan struct{}, 1), results: make(chan observationResult, 64), acks: make(chan applicationResult, 64), slots: make(chan struct{}, 8)}, nil
}

func (c *Controller) Notify() {
	c.dirty.Store(true)
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Controller) Start(parent context.Context) context.CancelFunc {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.run(ctx)
	}()
	return func() { cancel(); <-done }
}

func (c *Controller) run(ctx context.Context) {
	c.scope, c.revision, c.policyRevision = rand.Text(), 0, 0
	c.engine, c.profile = nil, engine.Profile{}
	c.local.SetEnabled(false)
	c.workers = map[string]context.CancelFunc{}
	c.lastEvent = map[string]string{}
	c.view.Store(nil)
	c.dirty.Store(true)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	defer c.stopWorkers()
	c.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			c.local.SetEnabled(false)
			c.status.Store(nil)
			return
		case <-c.wake:
			c.tick(ctx)
		case <-ticker.C:
			c.tick(ctx)
		case result := <-c.results:
			c.respond(ctx, result)
		case result := <-c.acks:
			c.appliedResult(result)
		}
	}
}

func (c *Controller) stopWorkers() {
	for _, cancel := range c.workers {
		cancel()
	}
	c.wg.Wait()
}

func (c *Controller) tick(ctx context.Context) {
	if err := c.refresh(ctx); err != nil {
		c.local.SetEnabled(false)
		c.status.Store(nil)
		return
	}
	w := c.view.Load()
	if w != nil && w.config.Enabled {
		c.evaluate(w)
	}
}

func (c *Controller) refresh(ctx context.Context) error {
	c.dirty.Store(false)
	p, err := c.store.loadPlan()
	if err != nil {
		return err
	}
	if c.dirty.Load() {
		return ErrConflict
	}
	key := p.fingerprint(c.now())
	old := c.view.Load()
	if old != nil && old.key == key {
		return nil
	}
	if old != nil && p.config.Revision < old.config.Revision {
		c.scope = rand.Text()
	}
	profile := p.config.Profile()
	if c.engine == nil || profile != c.profile {
		c.engine, err = engine.New(profile)
		if err != nil {
			return err
		}
		c.profile = profile
	}
	policies, users, incomplete, limitSources := p.policies(c.now())
	if err := c.local.Configure(profile); err != nil {
		return err
	}
	c.local.SetUsers(users)
	c.local.SetIncomplete(incomplete)
	c.local.SetEnabled(p.config.Enabled)
	c.engine.SetPolicies(policies)
	c.policyRevision++
	w := &work{revision: c.policyRevision, limitSources: limitSources, key: key, scope: c.scope, config: p.config, policies: policies,
		clients: map[string]uint{}, targets: p.targets()}
	for _, client := range p.clients {
		w.clients[client.key()] = client.ID
	}
	c.view.Store(w)
	c.applied, c.expected = map[string]string{}, map[string]string{}
	initial := &statusView{enabled: p.config.Enabled, updated: c.now(), clients: map[uint]ClientStatus{}}
	for key, policy := range policies {
		initial.clients[w.clients[key]] = ClientStatus{
			ClientID: w.clients[key], Limit: policy.Limit, LimitSource: limitSources[key], RequestedRevision: w.revision,
		}
	}
	c.status.Store(initial)
	c.resetWorkers(ctx, w)
	return nil
}

func (p plan) targets() map[string]target {
	access := map[uint]model.NodeAccessState{}
	for _, value := range p.access {
		access[value.NodeId] = value
	}
	result := map[string]target{}
	for _, node := range p.nodes {
		state := access[node.Id]
		if !node.Enable || state.AppliedRevision == 0 || state.AppliedRevision != state.DesiredRevision {
			continue
		}
		result[fmt.Sprintf("node:%d", node.Id)] = target{node: node,
			identity: wire.Identity{NodeID: uint64(node.Id), Epoch: node.ControlEpoch, AccessRevision: state.AppliedRevision}}
	}
	return result
}

func (c *Controller) resetWorkers(ctx context.Context, w *work) {
	for _, cancel := range c.workers {
		cancel()
	}
	c.workers = map[string]context.CancelFunc{}
	if c.transport == nil {
		return
	}
	for source, target := range w.targets {
		workerCtx, cancel := context.WithCancel(ctx)
		c.workers[source] = cancel
		c.wg.Go(func() { c.worker(workerCtx, w, source, target) })
	}
}

func (c *Controller) worker(ctx context.Context, w *work, source string, target target) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if delivered := c.exchange(ctx, w, source, target); delivered && !w.config.Enabled {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Controller) exchange(parent context.Context, w *work, source string, target target) bool {
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-parent.Done():
		return false
	}
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	peer, err := c.transport.Open(ctx, target.node)
	result := observationResult{work: w, source: source, err: err, answer: make(chan *wire.Decision, 1)}
	if err == nil {
		defer peer.Close()
		config := wire.Configuration{Version: wire.Version, Identity: target.identity, Scope: w.scope,
			Revision: w.config.Revision, Enabled: w.config.Enabled, Profile: wire.Profile{
				ActivitySeconds: w.config.ActivitySeconds, TransitionSeconds: w.config.TransitionSeconds,
				ConfirmationSeconds: uint32(w.config.Profile().Confirmation / time.Second)}}
		result.header, result.entries, result.requested, result.err = peer.Observe(ctx, config)
	}
	if !w.config.Enabled {
		return result.err == nil
	}
	select {
	case c.results <- result:
	case <-ctx.Done():
		return false
	}
	select {
	case decision := <-result.answer:
		if decision != nil && result.err == nil && c.view.Load() == w && !c.dirty.Load() {
			err := peer.Apply(ctx, *decision)
			ack := applicationResult{work: w, source: source, signature: ruleSignature(decision.Rules), err: err}
			select {
			case c.acks <- ack:
			case <-ctx.Done():
			}
		}
	case <-ctx.Done():
	}
	return result.err == nil
}

func (c *Controller) respond(ctx context.Context, result observationResult) {
	if c.dirty.Load() {
		if err := c.refresh(ctx); err != nil {
			result.answer <- nil
			return
		}
	}
	w := c.view.Load()
	if w != result.work || !w.config.Enabled {
		result.answer <- nil
		return
	}
	if result.err != nil {
		c.engine.RemoveSource(result.source)
		c.evaluate(w)
		result.answer <- nil
		return
	}
	snapshot := engineSnapshot(result.source, result.header, result.entries)
	c.engine.SetSource(result.source, snapshot.Boot)
	if err := c.engine.Accept(snapshot, result.requested, c.now()); err != nil {
		c.engine.RemoveSource(result.source)
		result.answer <- nil
		return
	}
	rules := c.evaluate(w)
	c.revision++
	header := result.header
	result.answer <- &wire.Decision{Version: wire.Version, Identity: header.Identity, Scope: w.scope,
		ConfigRevision: w.config.Revision, Boot: header.Boot, Sequence: header.Sequence,
		Challenge: header.Challenge, Revision: c.revision, Rules: rules[result.source]}
}

func engineSnapshot(source string, header wire.Header, entries []wire.Observation) engine.Snapshot {
	snapshot := engine.Snapshot{Source: source, Boot: header.Boot, Sequence: header.Sequence, Complete: header.Complete}
	for _, value := range entries {
		if value.Incomplete {
			snapshot.IncompleteClients = append(snapshot.IncompleteClients, value.Client)
			continue
		}
		snapshot.Entries = append(snapshot.Entries, engine.Observation{Client: value.Client, Address: value.Address,
			ActivityAge: duration(value.ActivityAgeMillis), AttemptAge: duration(value.AttemptAgeMillis)})
	}
	return snapshot
}

func duration(value *int64) *time.Duration {
	if value == nil {
		return nil
	}
	d := time.Duration(*value) * time.Millisecond
	return &d
}

func (c *Controller) evaluate(w *work) map[string][]wire.Rule {
	requested := c.now()
	report := c.local.Report("local")
	if c.ready != nil && !c.ready() {
		report.Snapshot.Complete = false
	}
	c.engine.SetSource("local", report.Snapshot.Boot)
	_ = c.engine.Accept(report.Snapshot, requested, c.now())
	now := c.now()
	view := &statusView{enabled: true, updated: now, clients: map[uint]ClientStatus{}}
	rules := map[string][]wire.Rule{}
	keys := slices.Collect(maps.Keys(w.policies))
	slices.Sort(keys)
	for _, id := range keys {
		result := c.engine.Evaluate(id, now)
		status := ClientStatus{ClientID: w.clients[id], LimitSource: w.limitSources[id], RequestedRevision: w.revision, Limit: result.Limit, Available: result.Complete,
			Checking: result.Checking, UpdatedAt: now.Unix(), Denied: len(result.Denied)}
		if result.Complete {
			count := result.Active
			status.ActiveCount = &count
		}
		view.clients[status.ClientID] = status
		for _, source := range w.policies[id].Sources {
			rules[source] = append(rules[source], wire.Rule{Client: id, Limit: result.Limit,
				Complete: result.Complete, Allowed: result.Allowed, Denied: result.Denied})
		}
	}
	c.revision++
	localRules := make([]ipruntime.Rule, len(rules["local"]))
	for index, value := range rules["local"] {
		localRules[index] = ipruntime.Rule{Client: value.Client, Limit: value.Limit,
			Complete: value.Complete, Allowed: value.Allowed, Denied: value.Denied}
	}
	for source, values := range rules {
		c.expected[source] = ruleSignature(values)
	}
	if err := c.local.Apply(ipruntime.Decision{Scope: w.scope, Challenge: report.Challenge, Revision: c.revision, Rules: localRules}); err == nil {
		c.applied["local"] = ruleSignature(rules["local"])
	}
	for id, policy := range w.policies {
		row := view.clients[w.clients[id]]
		row.Applied = row.Available && c.isApplied(policy.Sources)
		if row.Applied {
			row.AppliedRevision = w.revision
		}
		view.clients[row.ClientID] = row
	}
	c.status.Store(view)
	c.recordEvents(w, rules, view)
	return rules
}

func (c *Controller) Status(ids []uint) (bool, []ClientStatus) {
	view := c.status.Load()
	rows := make([]ClientStatus, 0, len(ids))
	if view == nil {
		return false, rows
	}
	fresh := c.now().Sub(view.updated) < engine.DefaultProfile().Freshness
	for _, id := range ids {
		row := view.clients[id]
		row.ClientID = id
		if !fresh || !view.enabled {
			row.Available, row.ActiveCount = false, nil
			row.Applied, row.Checking, row.AppliedRevision = false, false, 0
		}
		rows = append(rows, row)
	}
	return view.enabled, rows
}

func (c *Controller) SaveConfiguration(value Configuration) (Configuration, error) {
	saved, err := c.store.SaveConfiguration(value)
	if err == nil {
		c.Notify()
	}
	return saved, err
}

var ErrUnavailable = errors.New("ip_control_unavailable")
