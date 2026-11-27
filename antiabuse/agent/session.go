package agent

import (
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/alireza0/s-ui/antiabuse/engine"
	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/antiabuse/wire"
)

var ErrConflict = errors.New("ip_control_identity_changed")

// Session is memory-only and uses the already authenticated control channel.
// It never restores a previously issued admission table after a process boot.
type Session struct {
	mu       sync.Mutex
	runtime  *ipruntime.Runtime
	now      func() time.Time
	identity wire.Identity
	config   wire.Configuration
	header   wire.Header
	entries  []wire.Observation
	issued   time.Time
}

func New(runtime *ipruntime.Runtime, now func() time.Time) *Session {
	if now == nil {
		now = time.Now
	}
	return &Session{runtime: runtime, now: now}
}

func (s *Session) SetIdentity(identity wire.Identity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.identity == identity {
		return
	}
	s.identity, s.config = identity, wire.Configuration{}
	s.clear()
	s.runtime.SetEnabled(false)
}

func (s *Session) Configure(value wire.Configuration) error {
	if err := value.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.current(value.Identity) || !s.challenge(value.Boot, value.Challenge) ||
		value.Scope == s.config.Scope && value.Revision < s.config.Revision {
		return ErrConflict
	}
	if value.Scope == s.config.Scope && value.Revision == s.config.Revision &&
		(value.Enabled != s.config.Enabled || value.Profile != s.config.Profile) {
		return ErrConflict
	}
	profile := engine.DefaultProfile()
	profile.Activity = time.Duration(value.Profile.ActivitySeconds) * time.Second
	profile.Transition = time.Duration(value.Profile.TransitionSeconds) * time.Second
	profile.Confirmation = time.Duration(value.Profile.ConfirmationSeconds) * time.Second
	if value.Scope != s.config.Scope || value.Revision != s.config.Revision {
		s.runtime.SetEnabled(false)
	}
	if err := s.runtime.Configure(profile); err != nil {
		return err
	}
	s.runtime.SetEnabled(value.Enabled)
	s.config = value
	s.clear()
	return nil
}

func (s *Session) current(identity wire.Identity) bool {
	return identity.Valid() && identity == s.identity
}

func (s *Session) challenge(boot, challenge string) bool {
	return s.header.Sequence != 0 && boot == s.header.Boot && challenge == s.header.Challenge &&
		!s.issued.IsZero() && s.now().Sub(s.issued) < engine.DefaultProfile().Freshness
}

func (s *Session) clear() {
	s.header, s.entries, s.issued = wire.Header{}, nil, time.Time{}
}

// State freezes the complete source observation for the short challenge life.
// Continuation pages must name its boot/sequence and never trigger a resample.
func (s *Session) State(identity wire.Identity, boot string, sequence uint64, offset int) (wire.Page, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.current(identity) || offset < 0 {
		return wire.Page{}, ErrConflict
	}
	if sequence == 0 {
		if offset != 0 || boot != "" {
			return wire.Page{}, wire.ErrInvalid
		}
		s.sample()
	} else if sequence != s.header.Sequence || !s.challenge(boot, s.header.Challenge) {
		return wire.Page{}, ErrConflict
	}
	if offset > len(s.entries) {
		return wire.Page{}, wire.ErrInvalid
	}
	end := min(offset+wire.PageSize, len(s.entries))
	page := wire.Page{Header: s.header, Offset: offset, Entries: append([]wire.Observation{}, s.entries[offset:end]...)}
	if end < len(s.entries) {
		page.Next = &end
	}
	return page, nil
}

func (s *Session) sample() {
	report := s.runtime.Report(strconv.FormatUint(s.identity.NodeID, 10))
	s.header = wire.Header{Version: wire.Version, Identity: s.identity,
		Scope: s.config.Scope, ConfigRevision: s.config.Revision, Boot: report.Snapshot.Boot,
		Sequence: report.Snapshot.Sequence, Challenge: report.Challenge, Complete: report.Snapshot.Complete}
	s.entries = make([]wire.Observation, 0, min(wire.MaxEntries, len(report.Snapshot.Entries)+len(report.Snapshot.IncompleteClients)))
	for _, entry := range report.Snapshot.Entries {
		s.entries = append(s.entries, wire.Observation{Client: entry.Client, Address: entry.Address,
			ActivityAgeMillis: milliseconds(entry.ActivityAge), AttemptAgeMillis: milliseconds(entry.AttemptAge)})
	}
	for _, id := range report.Snapshot.IncompleteClients {
		if len(s.entries) == wire.MaxEntries {
			s.header.Complete = false
			break
		}
		s.entries = append(s.entries, wire.Observation{Client: id, Incomplete: true})
	}
	s.header.Total, s.issued = len(s.entries), s.now()
}

func milliseconds(age *time.Duration) *int64 {
	if age == nil {
		return nil
	}
	value := age.Milliseconds()
	return &value
}

func (s *Session) Apply(value wire.Decision) error {
	if err := value.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.current(value.Identity) || value.Scope != s.config.Scope || value.ConfigRevision != s.config.Revision ||
		value.Sequence != s.header.Sequence || !s.challenge(value.Boot, value.Challenge) {
		return ErrConflict
	}
	rules := make([]ipruntime.Rule, len(value.Rules))
	for index, value := range value.Rules {
		rules[index] = ipruntime.Rule{Client: value.Client, Limit: value.Limit,
			Complete: value.Complete, Allowed: value.Allowed, Denied: value.Denied}
	}
	if err := s.runtime.Apply(ipruntime.Decision{Scope: value.Scope, Challenge: value.Challenge,
		Revision: value.Revision, Rules: rules}); err != nil {
		return err
	}
	s.clear()
	return nil
}
