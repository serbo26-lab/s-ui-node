package engine

import (
	"errors"
	"net/netip"
	"time"
)

// Profile keeps user-facing windows separate from transport freshness.
type Profile struct {
	Activity     time.Duration
	Transition   time.Duration
	Confirmation time.Duration
	Freshness    time.Duration
	MaxEntries   int
}

func DefaultProfile() Profile {
	return Profile{
		Activity: time.Minute, Transition: 2 * time.Minute,
		Confirmation: 30 * time.Second, Freshness: 15 * time.Second,
		MaxEntries: 65536,
	}
}

func (p Profile) Validate() error {
	if p.Activity <= 0 || p.Transition < p.Activity || p.Confirmation <= 0 ||
		p.Confirmation > p.Transition || p.Freshness <= 0 || p.Freshness >= p.Activity ||
		p.MaxEntries < 1 {
		return errors.New("invalid IP control profile")
	}
	return nil
}

// Address strips transport details and groups temporary IPv6 addresses by /64.
func Address(addr netip.Addr) (netip.Prefix, error) {
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
		return netip.Prefix{}, errors.New("invalid source address")
	}
	addr = addr.WithZone("").Unmap()
	bits := 64
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

// EffectiveLimit preserves explicit zero and never converts inheritance on read.
func EffectiveLimit(group string, individual *uint32, groups map[string]uint32) uint32 {
	if individual != nil {
		return *individual
	}
	return groups[group]
}
