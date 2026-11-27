package nodeagent

import (
	"encoding/json"
	"maps"
	"slices"

	ipagent "github.com/alireza0/s-ui/antiabuse/agent"
	"github.com/alireza0/s-ui/antiabuse/engine"
	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/antiabuse/wire"
)

func (r *CoreRuntime) initializeIPControl() {
	r.ipOnce.Do(func() {
		var err error
		r.ipRuntime, err = ipruntime.New(engine.DefaultProfile(), nil)
		if err != nil {
			panic(err)
		}
		r.ipSession = ipagent.New(r.ipRuntime, nil)
	})
}

func (r *CoreRuntime) IPControlSession() *ipagent.Session {
	return r.ipSession
}

type ipInbound struct {
	Tag     string `json:"tag"`
	Type    string `json:"type"`
	Method  string `json:"method"`
	Version uint   `json:"version"`
	Managed bool   `json:"managed"`
	Users   []struct {
		Name     string `json:"name"`
		Username string `json:"username"`
	} `json:"users"`
}

// Called with r.mu held, after the corresponding access/configuration applied.
func (r *CoreRuntime) updateIPControl(access AccessSnapshot) {
	r.initializeIPControl()
	bindings := map[ipruntime.Identity]string{}
	incomplete := map[string]bool{}
	var config struct {
		Inbounds []ipInbound `json:"inbounds"`
	}
	if json.Unmarshal(r.config, &config) == nil {
		for _, inbound := range config.Inbounds {
			inbound.bindIPUsers(access, bindings, incomplete)
		}
	} else {
		for _, grant := range access.Clients {
			incomplete[grant.TrafficID] = true
		}
	}
	r.ipRuntime.SetUsers(bindings)
	r.ipRuntime.SetIncomplete(slices.Collect(maps.Keys(incomplete)))
	r.ipSession.SetIdentity(wire.Identity{NodeID: access.NodeID, Epoch: access.Epoch, AccessRevision: access.Revision})
}

func (in ipInbound) bindIPUsers(access AccessSnapshot, bindings map[ipruntime.Identity]string, incomplete map[string]bool) {
	aliases := ipAliases(access, in.Type, in.Method)
	covered := map[string]bool{}
	for _, user := range in.Users {
		name := user.Name
		if UsernameAuth(in.Type) {
			name = user.Username
		}
		if ids := aliases[name]; name != "" && len(ids) == 1 {
			bindings[ipruntime.Identity{Inbound: in.Tag, User: name}] = ids[0]
			covered[ids[0]] = true
		}
	}
	for _, ids := range aliases {
		for _, id := range ids {
			if !covered[id] || len(ids) != 1 || in.Type == "shadowtls" && in.Version < 3 || in.Managed {
				incomplete[id] = true
			}
		}
	}
}

func ipAliases(access AccessSnapshot, protocol, method string) map[string][]string {
	aliases := map[string][]string{}
	for _, grant := range access.Clients {
		credential, ok := grant.Credentials[CredentialKey(protocol, method)]
		if !ok || grant.TrafficID == "" {
			continue
		}
		name := grant.Name
		if UsernameAuth(protocol) {
			var auth struct {
				Username string `json:"username"`
			}
			if json.Unmarshal(credential, &auth) != nil {
				continue
			}
			name = auth.Username
		}
		aliases[name] = append(aliases[name], grant.TrafficID)
	}
	return aliases
}

func (m *ManagerV2) ipControlReady() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running && m.state.AppliedAccess != nil && m.state.AppliedAccess.Revision == m.state.Access.Revision
}
