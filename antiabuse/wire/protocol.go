package wire

import (
	"errors"
	"math"
	"net/netip"
	"reflect"
	"slices"
)

const Version = 1
const PageSize = 512
const MaxEntries = 65536

const ConfigPath = "/v2/ip-control/config"
const StatePath = "/v2/ip-control/state"
const DecisionPath = "/v2/ip-control/decision"

var ErrInvalid = errors.New("invalid IP control message")

type Identity struct {
	NodeID         uint64 `json:"node_id"`
	Epoch          string `json:"epoch"`
	AccessRevision uint64 `json:"access_revision"`
}

func (id Identity) Valid() bool {
	return id.NodeID > 0 && token(id.Epoch) && id.AccessRevision > 0
}

type Profile struct {
	ActivitySeconds     uint32 `json:"activity_seconds"`
	TransitionSeconds   uint32 `json:"transition_seconds"`
	ConfirmationSeconds uint32 `json:"confirmation_seconds"`
}

type Configuration struct {
	Version   uint32   `json:"version"`
	Identity  Identity `json:"identity"`
	Scope     string   `json:"scope"`
	Revision  uint64   `json:"revision"`
	Enabled   bool     `json:"enabled"`
	Profile   Profile  `json:"profile"`
	Boot      string   `json:"boot"`
	Challenge string   `json:"challenge"`
}

func (c Configuration) Validate() error {
	if c.Version != Version || !c.Identity.Valid() || !token(c.Scope) || !token(c.Boot) || !token(c.Challenge) || c.Revision == 0 ||
		c.Profile.ActivitySeconds <= 15 || c.Profile.TransitionSeconds < c.Profile.ActivitySeconds ||
		c.Profile.ConfirmationSeconds == 0 || c.Profile.ConfirmationSeconds > c.Profile.TransitionSeconds {
		return ErrInvalid
	}
	return nil
}

type Observation struct {
	Client            string     `json:"client"`
	Address           netip.Addr `json:"address"`
	Incomplete        bool       `json:"incomplete,omitempty"`
	ActivityAgeMillis *int64     `json:"activity_age_ms,omitempty"`
	AttemptAgeMillis  *int64     `json:"attempt_age_ms,omitempty"`
}

type Header struct {
	Version        uint32   `json:"version"`
	Identity       Identity `json:"identity"`
	Scope          string   `json:"scope"`
	ConfigRevision uint64   `json:"config_revision"`
	Boot           string   `json:"boot"`
	Sequence       uint64   `json:"sequence"`
	Challenge      string   `json:"challenge"`
	Complete       bool     `json:"complete"`
	Total          int      `json:"total"`
}

type Page struct {
	Header
	Offset  int           `json:"offset"`
	Next    *int          `json:"next"`
	Entries []Observation `json:"entries"`
}

type Rule struct {
	Client   string         `json:"client"`
	Limit    uint32         `json:"limit"`
	Complete bool           `json:"complete"`
	Allowed  []netip.Prefix `json:"allowed"`
	Denied   []netip.Prefix `json:"denied"`
}

type Decision struct {
	Version        uint32   `json:"version"`
	Identity       Identity `json:"identity"`
	Scope          string   `json:"scope"`
	ConfigRevision uint64   `json:"config_revision"`
	Boot           string   `json:"boot"`
	Sequence       uint64   `json:"sequence"`
	Challenge      string   `json:"challenge"`
	Revision       uint64   `json:"revision"`
	Rules          []Rule   `json:"rules"`
}

func (d Decision) Validate() error {
	if d.Version != Version || !d.Identity.Valid() || !token(d.Scope) || !token(d.Boot) ||
		!token(d.Challenge) || d.ConfigRevision == 0 || d.Sequence == 0 || d.Revision == 0 || len(d.Rules) > MaxEntries {
		return ErrInvalid
	}
	return nil
}

func token(value string) bool { return value != "" && len(value) <= 128 }

// Assembly never publishes a partial snapshot or combines pages from different
// source boots, configurations, access revisions, or observation sequences.
type Assembly struct {
	identity Identity
	scope    string
	revision uint64
	header   *Header
	entries  []Observation
	done     bool
}

func NewAssembly(identity Identity, scope string, revision uint64) *Assembly {
	return &Assembly{identity: identity, scope: scope, revision: revision}
}

func (a *Assembly) Add(page Page) error {
	if a.done || page.Offset != len(a.entries) || page.Entries == nil || len(page.Entries) > PageSize {
		return ErrInvalid
	}
	if err := a.checkHeader(page.Header); err != nil {
		return err
	}
	count := page.Offset + len(page.Entries)
	if !page.validCount(count) {
		return ErrInvalid
	}
	for _, entry := range page.Entries {
		if !entry.valid() {
			return ErrInvalid
		}
	}
	if a.header == nil {
		header := page.Header
		a.header = &header
	}
	a.entries = append(a.entries, page.Entries...)
	a.done = page.Next == nil
	return nil
}

func (p Page) validCount(count int) bool {
	if count > p.Total {
		return false
	}
	if p.Next == nil {
		return count == p.Total
	}
	return *p.Next == count && count < p.Total && len(p.Entries) > 0
}

func (a *Assembly) checkHeader(header Header) error {
	if header.Version != Version || header.Identity != a.identity || header.Scope != a.scope ||
		header.ConfigRevision != a.revision || !token(header.Boot) || !token(header.Challenge) ||
		header.Sequence == 0 || header.Total < 0 || header.Total > MaxEntries {
		return ErrInvalid
	}
	if a.header != nil && !reflect.DeepEqual(*a.header, header) {
		return ErrInvalid
	}
	return nil
}

func (a *Assembly) Result() (Header, []Observation, error) {
	if !a.done || a.header == nil {
		return Header{}, nil, ErrInvalid
	}
	return *a.header, slices.Clone(a.entries), nil
}

func (o Observation) valid() bool {
	if !token(o.Client) || !validAge(o.ActivityAgeMillis) || !validAge(o.AttemptAgeMillis) {
		return false
	}
	if o.Incomplete {
		return !o.Address.IsValid() && o.ActivityAgeMillis == nil && o.AttemptAgeMillis == nil
	}
	return o.Address.IsValid() && !o.Address.IsUnspecified() && !o.Address.IsMulticast() &&
		(o.ActivityAgeMillis != nil || o.AttemptAgeMillis != nil)
}

func validAge(age *int64) bool {
	return age == nil || *age >= 0 && *age <= math.MaxInt64/1000000
}
