package nodeagent

import (
	"encoding/json"

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

// Called with r.mu held, after the corresponding access/configuration applied.
func (r *CoreRuntime) updateIPControl(access AccessSnapshot) {
	r.initializeIPControl()
	bindings := map[ipruntime.Identity]string{}
	var config struct {
		Inbounds []struct {
			Tag   string `json:"tag"`
			Type  string `json:"type"`
			Users []struct {
				Name     string `json:"name"`
				Username string `json:"username"`
			} `json:"users"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(r.config, &config) == nil {
		for _, inbound := range config.Inbounds {
			aliases := ipAliases(access, inbound.Type)
			for _, user := range inbound.Users {
				name := user.Name
				if UsernameAuth(inbound.Type) {
					name = user.Username
				}
				if id := aliases[name]; name != "" && id != "" {
					bindings[ipruntime.Identity{Inbound: inbound.Tag, User: name}] = id
				}
			}
		}
	}
	r.ipRuntime.SetUsers(bindings)
	r.ipSession.SetIdentity(wire.Identity{NodeID: access.NodeID, Epoch: access.Epoch, AccessRevision: access.Revision})
}

func ipAliases(access AccessSnapshot, protocol string) map[string]string {
	aliases := map[string]string{}
	for _, grant := range access.Clients {
		credential, ok := grant.Credentials[protocol]
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
		aliases[name] = grant.TrafficID
	}
	return aliases
}

func (m *ManagerV2) ipControlReady() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running && m.state.AppliedAccess != nil && m.state.AppliedAccess.Revision == m.state.Access.Revision
}
