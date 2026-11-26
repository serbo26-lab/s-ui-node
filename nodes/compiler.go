// Package nodes owns remote node configuration; it never calls local corePtr.
package nodes

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/nodeagent"
	"gorm.io/gorm"
)

type Publication struct {
	Id      uint   `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Enable  bool   `json:"enable"`
	Managed bool   `json:"managed,omitempty"`
}

// Snapshot is private: it includes server configuration and user credentials.
type Snapshot struct {
	TemplateId      uint                 `json:"template_id,omitempty"`
	TemplateVersion uint64               `json:"template_version,omitempty"`
	SettingsVersion uint64               `json:"settings_version,omitempty"`
	Node            Publication          `json:"node"`
	Inbounds        []model.NodeInbound  `json:"inbounds"`
	Deployment      nodeagent.Deployment `json:"deployment"`
}

func serverTag(nodeID, inboundID uint) string {
	return fmt.Sprintf("node-%d-inbound-%d", nodeID, inboundID)
}
func userName(client model.Client) string {
	if client.NodeGeneration == 0 {
		return fmt.Sprintf("client/%d", client.Id)
	}
	return fmt.Sprintf("client/%d/g%d", client.Id, client.NodeGeneration)
}

func Compile(tx *gorm.DB, node model.Node) (Snapshot, error) {
	return compileNode(tx, node, node.AgentProtocol != 2)
}

func compileNode(tx *gorm.DB, node model.Node, withUsers bool) (Snapshot, error) {
	s := Snapshot{Node: Publication{Id: node.Id, Name: node.Name, Address: node.LinkAddress, Enable: node.Enable}, Inbounds: []model.NodeInbound{},
		Deployment: nodeagent.Deployment{NodeID: uint64(node.Id), Users: []nodeagent.Access{}}}
	if node.TemplateTargetVersion > 0 {
		s.TemplateId, s.TemplateVersion, s.SettingsVersion = node.TemplateId, node.MaterializedTemplateVersion, node.SettingsVersion
	}
	var installation model.NodeInstallation
	s.Node.Managed = tx.First(&installation, whereNodeID, node.Id).Error == nil || node.TemplateTargetVersion > 0
	config := map[string]interface{}{"log": map[string]interface{}{"level": "error"}, "outbounds": []interface{}{map[string]interface{}{"type": "direct", "tag": "direct"}}, "route": map[string]interface{}{"final": "direct"}}
	// Disable removes the listeners even when the saved configuration cannot be applied.
	var base json.RawMessage
	if node.Enable {
		base = node.Config
		if len(base) == 0 && node.TemplateId != 0 {
			var template model.NodeTemplate
			if err := tx.First(&template, node.TemplateId).Error; err != nil {
				return s, err
			}
			base = template.Config
		}
	}
	if len(base) > 0 && string(base) != "null" {
		resolved := base
		var err error
		if node.TemplateTargetVersion == 0 {
			resolved, err = resolveNodeParameters(base, node)
			if err != nil {
				return s, err
			}
		}
		if err := json.Unmarshal(resolved, &config); err != nil {
			return s, err
		}
	}
	var inbounds []model.NodeInbound
	if node.Enable {
		if err := tx.Where("node_id = ? AND enable = ? AND retired = ?", node.Id, true, false).Order("id").Find(&inbounds).Error; err != nil {
			return s, err
		}
	}
	serverInbounds := make([]interface{}, 0, len(inbounds))
	var detours map[string]string
	if node.TemplateTargetVersion > 0 {
		var err error
		detours, err = compileNodeDetours(inbounds)
		if err != nil {
			return s, err
		}
	}
	seenUsers := map[uint]bool{}
	for _, inbound := range inbounds {
		resolved := inbound.Options
		var err error
		if node.TemplateTargetVersion == 0 {
			resolved, err = resolveNodeParameters(inbound.Options, node)
			if err != nil {
				return s, err
			}
		}
		inbound.Options = resolved
		if len(inbound.ClientTLS) > 0 && string(inbound.ClientTLS) != "null" {
			inbound.ClientTLS, err = resolveNodeParameters(inbound.ClientTLS, node)
			if err != nil {
				return s, err
			}
		}
		var options map[string]interface{}
		if err := json.Unmarshal(inbound.Options, &options); err != nil || options == nil {
			return s, errors.New("invalid node inbound options")
		}
		options["type"], options["tag"] = inbound.Type, serverTag(node.Id, inbound.Id)
		if target := detours[inbound.ConnectionKey]; target != "" {
			options["detour"] = target
		}
		var clients []model.Client
		if !withUsers {
			err = nil
		} else if node.AssignmentMode == model.NodeAssignmentWhole {
			err = tx.Model(&model.Client{}).Joins("JOIN client_nodes AS binding ON binding.client_id = clients.id").Where("binding.node_id = ? AND binding.active = ? AND clients.enable = ?", node.Id, true, true).Order("clients.id").Find(&clients).Error
		} else {
			err = tx.Model(&model.Client{}).Joins("JOIN client_node_inbounds AS binding ON binding.client_id = clients.id").
				Where("binding.node_inbound_id = ? AND clients.enable = ?", inbound.Id, true).Order("clients.id").Find(&clients).Error
		}
		if err != nil {
			return s, err
		}
		users := []interface{}{}
		for _, client := range clients {
			if client.Expiry > 0 && client.Expiry <= time.Now().Unix() {
				continue
			}
			var credentials map[string]map[string]interface{}
			if err := json.Unmarshal(client.Config, &credentials); err != nil {
				return s, err
			}
			user := credentials[inbound.Type]
			if user == nil {
				return s, fmt.Errorf("client %d lacks credentials for %s", client.Id, inbound.Type)
			}
			user["name"] = userName(client)
			if inbound.Type == "vless" && !supportsVision(options) {
				delete(user, "flow")
			}
			users = append(users, user)
			if !seenUsers[client.Id] {
				s.Deployment.Users = append(s.Deployment.Users, nodeagent.Access{Name: userName(client), Expires: client.Expiry})
				seenUsers[client.Id] = true
			}
		}
		if withUsers {
			options["users"] = users
		} else {
			delete(options, "users")
		}
		serverInbounds = append(serverInbounds, options)
		s.Inbounds = append(s.Inbounds, inbound)
	}
	config["inbounds"] = serverInbounds
	b, err := json.Marshal(config)
	if err == nil {
		err = nodeagent.ValidateCertificateReferences(b)
	}
	s.Deployment.Config = b
	return s, err
}

func clientTLS(inbound model.NodeInbound) (json.RawMessage, json.RawMessage, error) {
	var options map[string]interface{}
	if err := json.Unmarshal(inbound.Options, &options); err != nil {
		return nil, nil, err
	}
	server, _ := options["tls"].(map[string]interface{})
	if server == nil || server["enabled"] != true {
		return nil, nil, nil
	}
	client := map[string]interface{}{}
	if len(inbound.ClientTLS) > 0 && string(inbound.ClientTLS) != "null" {
		if err := json.Unmarshal(inbound.ClientTLS, &client); err != nil {
			return nil, nil, err
		}
	}
	publicServer := map[string]interface{}{}
	for _, key := range []string{"enabled", "server_name", "alpn", "min_version", "max_version", "cipher_suites", "curve_preferences", "handshake_timeout", "certificate"} {
		if value, ok := server[key]; ok {
			publicServer[key] = value
			if key != "certificate" {
				client[key] = value
			}
		}
	}
	if reality, ok := server["reality"].(map[string]interface{}); ok && reality["enabled"] == true {
		key, _ := reality["private_key"].(string)
		decoded, err := base64.RawURLEncoding.DecodeString(key)
		if err != nil {
			return nil, nil, errors.New("invalid REALITY private key encoding")
		}
		private, err := ecdh.X25519().NewPrivateKey(decoded)
		if err != nil {
			return nil, nil, errors.New("invalid REALITY private key")
		}
		client["reality"] = map[string]interface{}{"enabled": true, "public_key": base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())}
		if client["utls"] == nil {
			client["utls"] = map[string]interface{}{"enabled": true, "fingerprint": "chrome"}
		}
		publicServer["reality"] = map[string]interface{}{"enabled": true, "short_id": reality["short_id"]}
	}
	if hasPrivateClientTLS(client) {
		return nil, nil, errors.New("private server TLS material must not be published to clients")
	}
	a, err := json.Marshal(publicServer)
	if err != nil {
		return nil, nil, err
	}
	b, err := json.Marshal(client)
	return a, b, err
}

func hasPrivateClientTLS(value interface{}) bool {
	switch x := value.(type) {
	case map[string]interface{}:
		for key, item := range x {
			if key == "private_key" || key == "key" || strings.HasSuffix(key, "_path") {
				return true
			}
			if hasPrivateClientTLS(item) {
				return true
			}
		}
	case []interface{}:
		for _, item := range x {
			if hasPrivateClientTLS(item) {
				return true
			}
		}
	}
	return false
}

func supportsVision(options map[string]interface{}) bool {
	tls, _ := options["tls"].(map[string]interface{})
	transport, _ := options["transport"].(map[string]interface{})
	return tls != nil && tls["enabled"] == true && (transport == nil || transport["type"] == nil || transport["type"] == "")
}
