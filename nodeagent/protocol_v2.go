package nodeagent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gofrs/uuid/v5"
)

const ProtocolV2 = 2

type Structure struct {
	NodeID   uint64          `json:"node_id"`
	Epoch    string          `json:"epoch"`
	Revision uint64          `json:"revision"`
	Config   json.RawMessage `json:"config"`
}

type Grant struct {
	Name        string                     `json:"name"`
	Expires     int64                      `json:"expires"`
	All         bool                       `json:"all"`
	Tags        []string                   `json:"tags,omitempty"`
	Credentials map[string]json.RawMessage `json:"credentials,omitempty"`
	// Only the one-time v1 import needs exact per-listener user fields.
	InboundCredentials map[string]json.RawMessage `json:"inbound_credentials,omitempty"`
}

type AccessSnapshot struct {
	NodeID   uint64  `json:"node_id"`
	Epoch    string  `json:"epoch"`
	Revision uint64  `json:"revision"`
	Clients  []Grant `json:"clients"`
}

func digestV2(value interface{}) string {
	body, _ := json.Marshal(value)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
func (s Structure) Digest() string      { return digestV2(s) }
func (a AccessSnapshot) Digest() string { return digestV2(a) }

func (s Structure) Validate() error {
	if s.NodeID == 0 || s.Epoch == "" || s.Revision == 0 {
		return errors.New("invalid structural identity")
	}
	var config map[string]json.RawMessage
	if json.Unmarshal(s.Config, &config) != nil || config == nil {
		return errors.New("structure must contain an object")
	}
	var inbounds []map[string]json.RawMessage
	if json.Unmarshal(config["inbounds"], &inbounds) != nil || inbounds == nil {
		return errors.New("structure needs an inbound array")
	}
	seen := map[string]bool{}
	for _, in := range inbounds {
		if _, exists := in["users"]; exists {
			return errors.New("structural spec must not contain users")
		}
		var tag, kind string
		if json.Unmarshal(in["tag"], &tag) != nil || tag == "" || seen[tag] {
			return errors.New("invalid structural inbound tag")
		}
		seen[tag] = true
		if json.Unmarshal(in["type"], &kind) != nil {
			return errors.New("invalid structural protocol")
		}
		if !SupportsInbound(kind, true) {
			return errors.New("unsupported structural protocol")
		}
	}
	return ValidateCertificateReferences(s.Config)
}

func (a AccessSnapshot) Validate() error {
	if a.NodeID == 0 || a.Epoch == "" || a.Revision == 0 || a.Clients == nil {
		return errors.New("invalid access identity or array")
	}
	seen := map[string]bool{}
	for _, g := range a.Clients {
		if g.Name == "" || seen[g.Name] || g.Expires < 0 || (g.All && len(g.Tags) > 0) || (!g.All && len(g.Tags) == 0) {
			return errors.New("invalid access grant")
		}
		seen[g.Name] = true
		tags := map[string]bool{}
		for _, tag := range g.Tags {
			if tag == "" || tags[tag] {
				return errors.New("duplicate access tag")
			}
			tags[tag] = true
		}
		for protocol, raw := range g.Credentials {
			if err := ValidateCredential(protocol, raw); err != nil {
				return err
			}
		}
		for tag, raw := range g.InboundCredentials {
			var value map[string]interface{}
			if !tags[tag] || json.Unmarshal(raw, &value) != nil || value == nil {
				return errors.New("invalid imported credential")
			}
		}
	}
	return nil
}

func ValidateCredential(kind string, raw json.RawMessage) error {
	if !SupportsInbound(kind, true) && kind != "shadowsocks16" {
		return errors.New("unsupported credential type")
	}
	var value map[string]interface{}
	if json.Unmarshal(raw, &value) != nil || value == nil {
		return errors.New("invalid credential object")
	}
	if NeedsUUID(kind) {
		id, _ := value["uuid"].(string)
		if _, err := uuid.FromString(id); err != nil {
			return errors.New("invalid credential UUID")
		}
	}
	if field := SecretField(kind); field != "" {
		password, _ := value[field].(string)
		if password == "" {
			return errors.New("credential password is missing")
		}
		if kind == "shadowsocks" || kind == "shadowsocks16" {
			want := 32
			if kind == "shadowsocks16" {
				want = 16
			}
			if key, err := base64.StdEncoding.DecodeString(password); err != nil || len(key) != want {
				return errors.New("invalid Shadowsocks user key")
			}
		}
	}
	if UsernameAuth(kind) {
		name, _ := value["username"].(string)
		if name == "" {
			return errors.New("credential username is missing")
		}
	}
	if flow, exists := value["flow"]; kind == "vless" && exists && flow != "" && flow != "xtls-rprx-vision" {
		return errors.New("invalid VLESS flow")
	}
	return nil
}

// Compose does not read a desired structure or roll access back with a spec.
func Compose(s Structure, a AccessSnapshot, now int64) ([]byte, error) {
	if s.NodeID != a.NodeID || s.Epoch != a.Epoch {
		return nil, ErrConflict
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(s.Config, &config); err != nil {
		return nil, err
	}
	var inbounds []map[string]json.RawMessage
	if err := json.Unmarshal(config["inbounds"], &inbounds); err != nil {
		return nil, err
	}
	for _, in := range inbounds {
		var tag, kind string
		_ = json.Unmarshal(in["tag"], &tag)
		_ = json.Unmarshal(in["type"], &kind)
		var method string
		_ = json.Unmarshal(in["method"], &method)
		credential := CredentialKey(kind, method)
		users := []map[string]interface{}{}
		for _, grant := range a.Clients {
			if grant.Expires > 0 && grant.Expires <= now {
				continue
			}
			allowed := grant.All
			for _, candidate := range grant.Tags {
				if candidate == tag {
					allowed = true
				}
			}
			if !allowed {
				continue
			}
			raw := grant.InboundCredentials[tag]
			imported := len(raw) > 0
			if !imported {
				raw = grant.Credentials[credential]
			}
			if len(raw) == 0 && ExtendedInbound(kind) {
				continue
			}
			var user map[string]interface{}
			if json.Unmarshal(raw, &user) != nil || user == nil {
				return nil, fmt.Errorf("missing credentials for granted protocol %s", kind)
			}
			if UsernameAuth(kind) {
				delete(user, "name")
			} else {
				user["name"] = grant.Name
			}
			if kind == "vless" && !imported {
				var tls map[string]interface{}
				var transport map[string]interface{}
				_ = json.Unmarshal(in["tls"], &tls)
				_ = json.Unmarshal(in["transport"], &transport)
				if tls["enabled"] != true || (transport["type"] != nil && transport["type"] != "") {
					delete(user, "flow")
				}
			}
			users = append(users, user)
		}
		if len(users) == 0 && ProxyInbound(kind) {
			// Some native inbounds allow anonymous access with an empty user
			// array. Keep them closed without changing listener topology.
			users = append(users, deniedProxyUser(kind, credential))
		}
		in["users"], _ = json.Marshal(users)
	}
	config["inbounds"], _ = json.Marshal(inbounds)
	return json.Marshal(config)
}

var deniedProxyKey = func() []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}()

func deniedProxyUser(kind, credential string) map[string]interface{} {
	key := deniedProxyKey
	if credential == "shadowsocks16" {
		key = key[:16]
	}
	secret := base64.StdEncoding.EncodeToString(key)
	name := "unassigned"
	if UsernameAuth(kind) {
		return map[string]interface{}{"username": name, "password": secret}
	}
	return map[string]interface{}{"name": name, SecretField(kind): secret}
}

func ImportV1(d Deployment, epoch string) (Structure, AccessSnapshot, error) {
	s := Structure{NodeID: d.NodeID, Epoch: epoch, Revision: d.Revision}
	a := AccessSnapshot{NodeID: d.NodeID, Epoch: epoch, Clients: []Grant{}}
	if err := d.Validate(); err != nil {
		return s, a, err
	}
	expires := map[string]int64{}
	for _, g := range d.Users {
		expires[g.Name] = g.Expires
	}
	var config map[string]json.RawMessage
	_ = json.Unmarshal(d.Config, &config)
	var inbounds []map[string]json.RawMessage
	_ = json.Unmarshal(config["inbounds"], &inbounds)
	byName := map[string]int{}
	for _, in := range inbounds {
		var tag string
		_ = json.Unmarshal(in["tag"], &tag)
		var users []map[string]json.RawMessage
		_ = json.Unmarshal(in["users"], &users)
		for _, user := range users {
			var name string
			_ = json.Unmarshal(user["name"], &name)
			delete(user, "name")
			index, ok := byName[name]
			if !ok {
				index = len(a.Clients)
				byName[name] = index
				a.Clients = append(a.Clients, Grant{Name: name, Expires: expires[name], Tags: []string{}, InboundCredentials: map[string]json.RawMessage{}})
			}
			g := &a.Clients[index]
			g.Tags = append(g.Tags, tag)
			g.InboundCredentials[tag], _ = json.Marshal(user)
		}
		delete(in, "users")
	}
	config["inbounds"], _ = json.Marshal(inbounds)
	s.Config, _ = json.Marshal(config)
	return s, a, s.Validate()
}
