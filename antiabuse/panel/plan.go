package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/alireza0/s-ui/antiabuse/engine"
	ipmodel "github.com/alireza0/s-ui/antiabuse/model"
	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/nodeagent"

	"gorm.io/gorm"
)

type policyClient struct {
	ID        uint            `gorm:"column:id"`
	CreatedAt int64           `gorm:"column:created_at"`
	Enable    bool            `gorm:"column:enable"`
	Name      string          `gorm:"column:name"`
	Group     string          `gorm:"column:group"`
	Config    json.RawMessage `gorm:"column:config"`
	Inbounds  json.RawMessage `gorm:"column:inbounds"`
	Expiry    int64           `gorm:"column:expiry"`
}

func (c policyClient) key() string { return fmt.Sprintf("%d:%d", c.ID, c.CreatedAt) }

type plan struct {
	config   Configuration
	clients  []policyClient
	rules    []ipmodel.ClientRule
	inbounds []model.Inbound
	bindings []model.ClientNode
	access   []model.NodeAccessState
	nodes    []model.Node
}

func (s *Store) loadPlan() (plan, error) {
	var p plan
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var err error
		p.config, err = NewStore(tx).Configuration()
		if err != nil {
			return err
		}
		queries := []struct {
			query *gorm.DB
			value any
		}{
			{tx.Table("clients").Select("id, created_at, enable, name, `group`, config, inbounds, expiry").Order("id"), &p.clients},
			{tx.Order("client_id"), &p.rules},
			{tx.Order("id"), &p.inbounds},
			{tx.Order("client_id, node_id"), &p.bindings},
			{tx.Order("node_id"), &p.access},
			{tx.Order("id"), &p.nodes},
		}
		for _, query := range queries {
			if err := query.query.Find(query.value).Error; err != nil {
				return err
			}
		}
		return nil
	})
	return p, err
}

// Only policy/identity fields contribute. Moving traffic counters or heartbeat
// timestamps must not invalidate a snapshot that is otherwise still current.
func (p plan) fingerprint(now time.Time) string {
	var targets []any
	for _, node := range p.nodes {
		targets = append(targets, []any{node.Id, node.Enable, node.Address, node.ControlEpoch, node.ManagementGeneration,
			node.ControlCertificate, node.DesiredRevision, node.AppliedRevision, node.RestoreAccessPending})
	}
	var inbounds []any
	for _, inbound := range p.inbounds {
		inbounds = append(inbounds, []any{inbound.Id, inbound.Tag, inbound.Type, inbound.Enable, string(inbound.Options)})
	}
	expired := make([]bool, len(p.clients))
	for index, client := range p.clients {
		expired[index] = client.Expiry > 0 && client.Expiry <= now.Unix()
	}
	body, _ := json.Marshal([]any{p.config, p.clients, p.rules, p.bindings, p.access, targets, inbounds, expired})
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func (p plan) policies(now time.Time) (map[string]engine.Policy, map[ipruntime.Identity]string, []string) {
	groups, individual, inbounds, sources := p.policyIndexes()
	policies := map[string]engine.Policy{}
	users := map[ipruntime.Identity]string{}
	unresolved := map[string]bool{}
	for _, client := range p.clients {
		if !client.Enable || client.Expiry > 0 && client.Expiry <= now.Unix() {
			continue
		}
		var override *uint32
		if row, ok := individual[client.ID]; ok && row.CreatedAt == client.CreatedAt {
			limit := row.Limit
			override = &limit
		}
		participant := slices.Clone(sources[client.ID])
		local, valid := localBindings(client, inbounds, users, unresolved)
		if local {
			participant = append(participant, "local")
		}
		if !valid {
			unresolved[client.key()] = true
		}
		policies[client.key()] = engine.Policy{Limit: engine.EffectiveLimit(client.Group, override, groups), Sources: participant}
	}
	var incomplete []string
	for id := range unresolved {
		incomplete = append(incomplete, id)
	}
	slices.Sort(incomplete)
	return policies, users, incomplete
}

func (p plan) policyIndexes() (map[string]uint32, map[uint]ipmodel.ClientRule, map[uint]model.Inbound, map[uint][]string) {
	groups := map[string]uint32{}
	for _, group := range p.config.Groups {
		groups[group.Group] = group.Limit
	}
	individual := map[uint]ipmodel.ClientRule{}
	for _, rule := range p.rules {
		individual[rule.ClientID] = rule
	}
	inbounds := map[uint]model.Inbound{}
	for _, inbound := range p.inbounds {
		inbounds[inbound.Id] = inbound
	}
	nodeEnabled := map[uint]bool{}
	for _, node := range p.nodes {
		nodeEnabled[node.Id] = node.Enable
	}
	sources := map[uint][]string{}
	for _, binding := range p.bindings {
		enabled, exists := nodeEnabled[binding.NodeId]
		if binding.Active && (!exists || enabled) {
			sources[binding.ClientId] = append(sources[binding.ClientId], fmt.Sprintf("node:%d", binding.NodeId))
		}
	}
	return groups, individual, inbounds, sources
}

func localBindings(client policyClient, inbounds map[uint]model.Inbound, users map[ipruntime.Identity]string, unresolved map[string]bool) (bool, bool) {
	var ids []uint
	var credentials map[string]json.RawMessage
	if json.Unmarshal(client.Inbounds, &ids) != nil || json.Unmarshal(client.Config, &credentials) != nil {
		return true, false
	}
	local, complete := false, true
	for _, id := range ids {
		inbound, ok := inbounds[id]
		if !ok || !inbound.Enable {
			continue
		}
		local = true
		name := localName(inbound, credentials)
		if name == "" {
			complete = false
			continue
		}
		key := ipruntime.Identity{Inbound: inbound.Tag, User: name}
		if owner, exists := users[key]; exists && owner != client.key() {
			complete = false
			if owner != "" {
				unresolved[owner] = true
			}
			unresolved[client.key()] = true
			users[key] = ""
			continue
		}
		users[key] = client.key()
	}
	return local, complete
}

func localName(inbound model.Inbound, credentials map[string]json.RawMessage) string {
	var options struct {
		Method  string `json:"method"`
		Version uint   `json:"version"`
		Managed bool   `json:"managed"`
	}
	if json.Unmarshal(inbound.Options, &options) != nil {
		return ""
	}
	if inbound.Type == "shadowtls" && options.Version < 3 || inbound.Type == "shadowsocks" && options.Managed {
		return ""
	}
	var user struct {
		Name     string `json:"name"`
		Username string `json:"username"`
	}
	if json.Unmarshal(credentials[nodeagent.CredentialKey(inbound.Type, options.Method)], &user) != nil {
		return ""
	}
	if nodeagent.UsernameAuth(inbound.Type) {
		return user.Username
	}
	return user.Name
}
