package source

import (
	"net/netip"
	"testing"
)

func TestForwardedTrustBoundary(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	for _, test := range []struct {
		name, peer, want string
		headers          []string
	}{
		{"direct spoof ignored", "198.51.100.1", "198.51.100.1", []string{"203.0.113.1"}},
		{"trusted edge", "192.0.2.1", "198.51.100.1", []string{"198.51.100.1"}},
		{"spoof before client ignored", "192.0.2.1", "198.51.100.1", []string{"invalid, 198.51.100.1"}},
		{"multiple header fields", "192.0.2.1", "198.51.100.1", []string{"203.0.113.1, 198.51.100.1", "192.0.2.2"}},
		{"mapped IPv4", "::ffff:192.0.2.1", "198.51.100.1", []string{"::ffff:198.51.100.1"}},
		{"IPv6 client", "192.0.2.1", "2001:db8::1", []string{"2001:db8::1"}},
		{"missing evidence", "192.0.2.1", "", nil},
		{"malformed evidence", "192.0.2.1", "", []string{"invalid"}},
		{"unresolved chain", "192.0.2.1", "", []string{"192.0.2.2"}},
		{"scoped address", "192.0.2.1", "", []string{"fe80::1%eth0"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := Forwarded(netip.MustParseAddr(test.peer), test.headers, proxies)
			want := netip.Addr{}
			if test.want != "" {
				want = netip.MustParseAddr(test.want)
			}
			if got != want {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestProxyNetworkValidation(t *testing.T) {
	for _, value := range []string{"0.0.0.0/0", "::/0", "192.0.2.1/24", "::ffff:192.0.2.0/120"} {
		if ValidateProxies([]netip.Prefix{netip.MustParsePrefix(value)}) == nil {
			t.Fatalf("accepted unsafe network %s", value)
		}
	}
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	if ValidateProxies([]netip.Prefix{prefix, prefix}) == nil || ValidateProxies(nil) != nil {
		t.Fatal("duplicate or empty network validation failed")
	}
}
