package runtime

import (
	"net/netip"
	"slices"

	"github.com/alireza0/s-ui/antiabuse/source"
)

type sourcePolicy struct{ proxies []netip.Prefix }

func (r *Runtime) SetTrustedProxies(proxies []netip.Prefix) error {
	if err := source.ValidateProxies(proxies); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.sources.Load()
	if old != nil && slices.Equal(old.proxies, proxies) {
		return nil
	}
	r.sources.Store(&sourcePolicy{proxies: slices.Clone(proxies)})
	if r.enabled.Load() {
		r.since.Store(r.stamp())
	}
	r.table.Store(nil)
	r.challenge = ""
	r.reservations = map[entryKey]int64{}
	return nil
}

func (r *Runtime) ForwardedSource(peer netip.Addr, headers []string) netip.Addr {
	policy := r.sources.Load()
	if policy == nil {
		return peer
	}
	return source.Forwarded(peer, headers, policy.proxies)
}
