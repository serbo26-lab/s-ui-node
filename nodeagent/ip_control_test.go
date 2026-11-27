package nodeagent

import (
	"encoding/json"
	"testing"

	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/antiabuse/wire"
)

func TestStatusAdvertisesOnlyImplementedIPControl(t *testing.T) {
	runtime := NewCoreRuntime()
	t.Cleanup(func() { _ = runtime.Close() })
	if status := NewManagerV2(1, nil, runtime).Status(); status.IPControlVersion != wire.Version {
		t.Fatal("implemented IP control missing from ordinary status")
	}
	if status := NewManagerV2(1, nil, nil).Status(); status.IPControlVersion != 0 {
		t.Fatal("unimplemented IP control advertised")
	}
}

func TestIPBindingsUseProtocolCredentialsAndRejectAmbiguousNames(t *testing.T) {
	for _, test := range []struct{ protocol, method, key, user string }{
		{"shadowsocks", "2022-blake3-aes-128-gcm", "shadowsocks16", "client/1"},
		{"shadowsocks", "2022-blake3-aes-256-gcm", "shadowsocks", "client/1"},
		{"socks", "", "socks", "account"},
	} {
		t.Run(test.key, func(t *testing.T) {
			access := AccessSnapshot{Clients: []Grant{{Name: "client/1", TrafficID: "1:100",
				Credentials: map[string]json.RawMessage{test.key: json.RawMessage(`{"username":"account"}`)}}}}
			var in ipInbound
			body, _ := json.Marshal(map[string]any{"tag": "in", "type": test.protocol, "method": test.method,
				"users": []any{map[string]string{"name": "client/1", "username": "account"}}})
			if err := json.Unmarshal(body, &in); err != nil {
				t.Fatal(err)
			}
			bindings, incomplete := map[ipruntime.Identity]string{}, map[string]bool{}
			in.bindIPUsers(access, bindings, incomplete)
			if bindings[ipruntime.Identity{Inbound: "in", User: test.user}] != "1:100" || len(incomplete) != 0 {
				t.Fatal("credential did not map to its stable client")
			}
			access.Clients = append(access.Clients, Grant{Name: "client/1", TrafficID: "2:200", Credentials: access.Clients[0].Credentials})
			bindings, incomplete = map[ipruntime.Identity]string{}, map[string]bool{}
			in.bindIPUsers(access, bindings, incomplete)
			if len(bindings) != 0 || !incomplete["1:100"] || !incomplete["2:200"] {
				t.Fatal("ambiguous clients reported complete")
			}
		})
	}
}

func TestMissingInboundIdentityIsNotACompleteZero(t *testing.T) {
	access := AccessSnapshot{Clients: []Grant{{Name: "client/1", TrafficID: "1:100",
		Credentials: map[string]json.RawMessage{"shadowtls": json.RawMessage(`{}`)}}}}
	in := ipInbound{Tag: "in", Type: "shadowtls", Version: 2}
	bindings, incomplete := map[ipruntime.Identity]string{}, map[string]bool{}
	in.bindIPUsers(access, bindings, incomplete)
	if len(bindings) != 0 || !incomplete["1:100"] {
		t.Fatal("unsupported identity hidden from the coordinator")
	}
}
