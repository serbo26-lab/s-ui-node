package nodes

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/alireza0/s-ui/database/model"
	"gorm.io/gorm"
)

func configureManagedNode(tx *gorm.DB, node *model.Node, i *model.NodeInstallation, r ProvisionRequest, ports map[string]int) error {
	if node.TemplateTargetVersion > 0 {
		return errors.New("live_template_installer_not_ready")
	}
	node.Name = r.Name
	node.Address = controlAddress(i.ControlPort)
	node.LinkAddress = i.Domain
	if node.LinkAddress == "" {
		node.LinkAddress = i.IP
	}
	if r.NodeId == 0 || !i.Ready {
		node.Enable = true
	}
	node.TemplateId = r.TemplateId
	config := map[string]interface{}{}
	_ = json.Unmarshal(node.Config, &config)
	if config == nil {
		config = map[string]interface{}{}
	}
	if err := configureManagedCertificate(config, i.Domain, r.Protocols); err != nil {
		return err
	}
	node.Config, _ = json.Marshal(config)
	if err := tx.Model(node).Select("name", "address", "link_address", "template_id", "enable", "config", "control_ca", "control_certificate", "control_key").Updates(node).Error; err != nil {
		return err
	}
	var existing []model.NodeInbound
	if err := tx.Where(whereNodeID, node.Id).Find(&existing).Error; err != nil {
		return err
	}
	selected := map[string]bool{}
	for _, kind := range r.Protocols {
		selected[kind] = true
		if err := configureManagedInbound(tx, node.Id, i.Domain, kind, ports[kind], existing); err != nil {
			return err
		}
	}
	for _, inbound := range existing {
		if !selected[inbound.Type] {
			if err := tx.Model(&inbound).Update("enable", false).Error; err != nil {
				return err
			}
		}
	}
	node.DesiredFingerprint = ""
	node.RejectedRevision = 0
	node.LastError = ""
	if err := tx.Model(node).Updates(map[string]interface{}{"desired_fingerprint": "", "rejected_revision": 0, "last_error": ""}).Error; err != nil {
		return err
	}
	_, err := Compile(tx, *node)
	return err
}

func managedCertificatesReady(node model.Node, protocols []string) bool {
	if !node.Enable {
		return true
	}
	expected := 0
	for _, p := range protocols {
		if p != "vless" {
			expected++
		}
	}
	if expected == 0 {
		return true
	}
	var report struct {
		Certificates []struct {
			State string `json:"state"`
		} `json:"certificates"`
	}
	if json.Unmarshal(node.TLSStatus, &report) != nil {
		return false
	}
	ready := 0
	for _, c := range report.Certificates {
		if c.State != "ready" {
			return false
		}
		ready++
	}
	return ready >= expected
}

func validateSimpleTemplate(value *model.NodeTemplate) error {
	if len(value.Protocols) == 0 || string(value.Protocols) == "null" {
		return nil
	}
	var protocols []string
	if json.Unmarshal(value.Protocols, &protocols) != nil {
		return errors.New("invalid_template_protocols")
	}
	protocols, err := supportedProtocols(protocols, false)
	if err != nil {
		return err
	}
	value.Protocols, _ = json.Marshal(protocols)
	return nil
}

func renameOnly(request ProvisionRequest, previous model.NodeInstallation) bool {
	if request.NodeId == 0 || !previous.Ready || request.Action != "install" || request.Password != "" || request.IP != previous.IP || request.SSHPort != previous.SSHPort || request.SSHUser != previous.SSHUser {
		return false
	}
	var prior []string
	if json.Unmarshal(previous.Protocols, &prior) != nil || len(prior) != len(request.Protocols) {
		return false
	}
	set := map[string]bool{}
	for _, p := range prior {
		set[p] = true
	}
	for _, p := range request.Protocols {
		if !set[p] {
			return false
		}
	}
	return true
}

func configureManagedCertificate(config map[string]interface{}, domain string, protocols []string) error {
	needsTLS := false
	for _, p := range protocols {
		if p != "vless" {
			needsTLS = true
		}
	}
	if needsTLS {
		s, err := loadAutomation()
		if err != nil {
			return err
		}
		token, err := openSecret(s.DNSToken)
		if err != nil {
			return err
		}
		// Public bootstrap resolvers keep DNS-01 checks independent of the host resolver.
		config["certificate_providers"] = []interface{}{map[string]interface{}{"type": "acme", "tag": "sui-managed-acme", "domain": []string{domain}, "email": s.Email, "dns01_challenge": map[string]interface{}{"provider": "cloudflare", "api_token": token, "resolvers": []string{"1.1.1.1:53", "8.8.8.8:53"}, "propagation_timeout": "3m"}}}
	}
	return nil
}

func configureManagedInbound(tx *gorm.DB, nodeID uint, domain, kind string, port int, existing []model.NodeInbound) error {
	var inbound model.NodeInbound
	found := false
	for _, old := range existing {
		if old.Type == kind {
			inbound = old
			found = true
			break
		}
	}
	options := map[string]interface{}{}
	if found {
		_ = json.Unmarshal(inbound.Options, &options)
	}
	if !found {
		inbound = model.NodeInbound{NodeId: nodeID, Type: kind, Tag: strings.ToUpper(kind), Enable: true}
		options = map[string]interface{}{"listen": "::"}
	}
	options["listen_port"] = port
	inbound.Enable = true
	if err := configureManagedInboundTLS(options, domain, kind); err != nil {
		return err
	}
	inbound.Options, _ = json.Marshal(options)
	if err := tx.Save(&inbound).Error; err != nil {
		return err
	}
	return nil
}

func configureManagedInboundTLS(options map[string]interface{}, domain, kind string) error {
	if kind == "vless" {
		if _, ok := options["tls"]; !ok {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			short := make([]byte, 8)
			if _, err = rand.Read(short); err != nil {
				return err
			}
			options["tls"] = map[string]interface{}{"enabled": true, "server_name": "www.cloudflare.com", "reality": map[string]interface{}{"enabled": true, "handshake": map[string]interface{}{"server": "www.cloudflare.com", "server_port": 443}, "private_key": base64.RawURLEncoding.EncodeToString(key.Bytes()), "short_id": []string{hex.EncodeToString(short)}}}
		}
	} else {
		options["tls"] = map[string]interface{}{"enabled": true, "server_name": domain, "certificate_provider": "sui-managed-acme", "alpn": []string{"h3"}}
		if kind == "tuic" {
			options["congestion_control"] = "cubic"
		}
	}
	return nil
}
