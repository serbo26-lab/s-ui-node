package runtime

import (
	"net/netip"
	"testing"

	"github.com/alireza0/s-ui/antiabuse/engine"
)

func TestSourcePolicyIsCopiedAndReloaded(t *testing.T) {
	r, err := New(engine.DefaultProfile(), nil)
	if err != nil {
		t.Fatal(err)
	}
	peer, client := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")
	proxies := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if err := r.SetTrustedProxies(proxies); err != nil {
		t.Fatal(err)
	}
	proxies[0] = netip.MustParsePrefix("203.0.113.0/24")
	if got := r.ForwardedSource(peer, []string{client.String()}); got != client {
		t.Fatal("caller changed source policy", got)
	}
	if err := r.SetTrustedProxies(nil); err != nil {
		t.Fatal(err)
	}
	if got := r.ForwardedSource(peer, []string{client.String()}); got != peer {
		t.Fatal("removed trust remained active", got)
	}
}
