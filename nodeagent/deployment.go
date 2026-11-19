// Package nodeagent runs a remotely managed sing-box independently of the panel.
package nodeagent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const ProtocolVersion = 1

// Access carries an absolute expiry; zero means no known expiry. Names identify
// the users in the generated server config, not client-facing inbound tags.
type Access struct {
	Name    string `json:"name"`
	Expires int64  `json:"expires"`
}

type Deployment struct {
	NodeID   uint64          `json:"node_id"`
	Revision uint64          `json:"revision"`
	Config   json.RawMessage `json:"config"`
	Users    []Access        `json:"users"`
}

func (d Deployment) Validate() error {
	if d.NodeID == 0 || d.Revision == 0 {
		return errors.New("node_id and revision must be positive")
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(d.Config, &config); err != nil || config == nil {
		return errors.New("config must be a JSON object")
	}
	access := make(map[string]bool, len(d.Users))
	for _, user := range d.Users {
		if user.Name == "" || access[user.Name] || user.Expires < 0 {
			return errors.New("invalid or duplicate access entry")
		}
		access[user.Name] = true
	}
	var inbounds []struct {
		Tag   string `json:"tag"`
		Type  string `json:"type"`
		Users []struct {
			Name string `json:"name"`
		} `json:"users"`
	}
	if err := json.Unmarshal(config["inbounds"], &inbounds); err != nil {
		return errors.New("config.inbounds must be an array")
	}
	tags := map[string]bool{}
	for _, inbound := range inbounds {
		if inbound.Tag == "" || tags[inbound.Tag] {
			return errors.New("inbound tags must be nonempty and unique within a node")
		}
		tags[inbound.Tag] = true
		switch inbound.Type {
		case "vless", "tuic", "hysteria2":
		default:
			return fmt.Errorf("unsupported node inbound type %q", inbound.Type)
		}
		seen := map[string]bool{}
		for _, user := range inbound.Users {
			if !access[user.Name] || seen[user.Name] {
				return errors.New("configured user lacks access metadata or is duplicated")
			}
			seen[user.Name] = true
		}
	}
	return nil
}

func (d Deployment) Digest() string {
	// json.Marshal compacts RawMessage, preserving large integer values.
	b, _ := json.Marshal(d)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Effective removes already expired users even while the panel is unavailable.
// The desired deployment is retained intact for recovery and revision checks.
func (d Deployment) Effective(now int64) ([]byte, error) {
	expired := map[string]bool{}
	for _, user := range d.Users {
		if user.Expires > 0 && user.Expires <= now {
			expired[user.Name] = true
		}
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(d.Config, &config); err != nil {
		return nil, err
	}
	var inbounds []map[string]json.RawMessage
	if err := json.Unmarshal(config["inbounds"], &inbounds); err != nil {
		return nil, err
	}
	for _, inbound := range inbounds {
		var users []json.RawMessage
		if err := json.Unmarshal(inbound["users"], &users); err != nil {
			return nil, err
		}
		kept := make([]json.RawMessage, 0, len(users))
		for _, raw := range users {
			var user struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(raw, &user); err != nil {
				return nil, err
			}
			if !expired[user.Name] {
				kept = append(kept, raw)
			}
		}
		inbound["users"], _ = json.Marshal(kept)
	}
	config["inbounds"], _ = json.Marshal(inbounds)
	return json.Marshal(config)
}
