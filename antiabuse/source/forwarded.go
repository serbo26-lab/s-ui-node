package source

import (
	"errors"
	"net/netip"
	"strings"
)

const MaxProxies = 128

// ValidateProxies rejects catch-all trust and noncanonical networks.
func ValidateProxies(proxies []netip.Prefix) error {
	if len(proxies) > MaxProxies {
		return errors.New("too many trusted proxies")
	}
	seen := map[netip.Prefix]bool{}
	for _, prefix := range proxies {
		if !prefix.IsValid() || prefix.Bits() == 0 || prefix != prefix.Masked() || prefix.Addr().Is4In6() || seen[prefix] {
			return errors.New("invalid trusted proxy network")
		}
		seen[prefix] = true
	}
	return nil
}

// Forwarded walks X-Forwarded-For from the authenticated network peer towards
// the client. Entries beyond the first untrusted hop cannot claim a new source.
// A trusted peer with missing or malformed evidence yields unknown, never its
// shared address. Forward proxy requests use their physical peer instead.
func Forwarded(peer netip.Addr, headers []string, proxies []netip.Prefix) netip.Addr {
	peer = peer.Unmap()
	if !trusted(peer, proxies) {
		return peer
	}
	if len(headers) == 0 || len(headers) > MaxProxies {
		return netip.Addr{}
	}
	current, hops := peer, 0
	for i := len(headers) - 1; i >= 0; i-- {
		parts := strings.Split(headers[i], ",")
		if hops+len(parts) > MaxProxies {
			return netip.Addr{}
		}
		for j := len(parts) - 1; j >= 0; j-- {
			if !trusted(current, proxies) {
				return current
			}
			address, err := netip.ParseAddr(strings.TrimSpace(parts[j]))
			if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
				return netip.Addr{}
			}
			current = address.Unmap()
			hops++
		}
	}
	if trusted(current, proxies) {
		return netip.Addr{}
	}
	return current
}

func trusted(address netip.Addr, proxies []netip.Prefix) bool {
	for _, prefix := range proxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
