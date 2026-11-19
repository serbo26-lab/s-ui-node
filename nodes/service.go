package nodes

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"golang.org/x/net/idna"
	"gorm.io/gorm"
)

type ControlTLS struct {
	CA          string `json:"ca"`
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
}

func IsObject(name string) bool {
	return name == "nodes" || name == "nodetemplates" || name == "nodeinbounds"
}

func Bundle() (map[string]interface{}, error) {
	db := database.GetDB()
	nodes := []model.Node{}
	templates := []model.NodeTemplate{}
	inbounds := []model.NodeInbound{}
	if err := db.Order("id").Find(&nodes).Error; err != nil {
		return nil, err
	}
	var members []model.NodeTemplateMember
	if err := db.Order("position").Find(&members).Error; err != nil {
		return nil, err
	}
	selections := map[uint][]uint{}
	for _, member := range members {
		selections[member.TemplateId] = append(selections[member.TemplateId], member.InboundId)
	}
	for i := range nodes {
		nodes[i].InboundTemplateIds = selections[nodes[i].TemplateId]
		nodes[i].AgentTrafficAvailable = nodes[i].TrafficProcess != ""
		nodes[i].DisableConfirmed = disableConfirmed(nodes[i])
		nodes[i].ControlTLSConfigured = nodes[i].ControlCA != "" && nodes[i].ControlCertificate != "" && nodes[i].ControlKey != ""
		fresh, err := Compile(db, nodes[i])
		if err != nil {
			nodes[i].Pending = true
			nodes[i].LastError = "compile_failed"
			continue
		}
		fingerprint, err := snapshotFingerprint(fresh)
		if err != nil {
			return nil, err
		}
		nodes[i].Pending = nodes[i].LastSeen == 0 || nodes[i].DesiredRevision == 0 || nodes[i].DesiredRevision != nodes[i].AppliedRevision || fingerprint != nodes[i].DesiredFingerprint
		if nodes[i].TemplateTargetVersion > 0 && (nodes[i].TemplateTargetVersion != nodes[i].MaterializedTemplateVersion || nodes[i].TemplateTargetVersion != nodes[i].AppliedTemplateVersion) {
			nodes[i].Pending = true
		}
	}
	if err := db.Order("id").Find(&templates).Error; err != nil {
		return nil, err
	}
	if err := db.Order("node_id,id").Find(&inbounds).Error; err != nil {
		return nil, err
	}
	for i := range inbounds {
		if inbounds[i].ConnectionKey != "" {
			redactInbound(&inbounds[i])
		}
	}
	installations := []model.NodeInstallation{}
	jobs := []model.NodeJob{}
	if err := db.Find(&installations).Error; err != nil {
		return nil, err
	}
	for index := range installations {
		installations[index].HostFingerprint = sshFingerprint(installations[index].HostKey)
	}
	if err := db.Order("created desc, id desc").Limit(30).Find(&jobs).Error; err != nil {
		return nil, err
	}
	accessStates := []model.NodeAccessState{}
	migrations := []model.NodeAssignmentMigration{}
	if err := db.Find(&accessStates).Error; err != nil {
		return nil, err
	}
	if err := db.Find(&migrations).Error; err != nil {
		return nil, err
	}
	tlsProfiles, err := listTLSProfiles(db)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"nodeaccess": accessStates, "nodemigrations": migrations, "nodes": nodes, "nodetemplates": templates, "nodeinbounds": inbounds, "installations": installations, "nodejobs": jobs, "tls_profiles": tlsProfiles}, nil
}

func validPublishedAddress(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		return net.ParseIP(value[1:len(value)-1]) != nil
	}
	if strings.ContainsAny(value, ": /?#@\\\t\r\n[]") {
		return false
	}
	ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(value, "."))
	if err != nil || len(ascii) > 253 {
		return false
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func validateManagementControl(node model.Node) error {
	u, err := url.Parse(node.Address)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("node management address must be an HTTPS origin without credentials/query")
	}
	if _, err := tls.X509KeyPair([]byte(node.ControlCertificate), []byte(node.ControlKey)); err != nil {
		return errors.New("invalid node controller certificate/key")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(node.ControlCA)) {
		return errors.New("invalid node server CA")
	}
	return nil
}

func validateControl(node model.Node) error {
	if err := validateManagementControl(node); err != nil {
		return err
	}
	if !validPublishedAddress(node.LinkAddress) {
		return errors.New("invalid published node address")
	}
	return nil
}

func Save(object, action string, data json.RawMessage, actor string) error {
	if !IsObject(object) {
		return errors.New("unknown Nodes object")
	}
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		if action == "setoverrides" || action == "privatecopy" || action == "sharedcopy" || action == "restoreversion" {
			return saveLiveAction(tx, object, action, data, actor)
		}
		var id uint
		var deleteRequest nodeDeleteRequest
		if action == "del" {
			if object == "nodes" {
				var err error
				deleteRequest, err = parseNodeDelete(data)
				if err != nil {
					return err
				}
				id = deleteRequest.Id
			} else if err := json.Unmarshal(data, &id); err != nil {
				return err
			}
		} else {
			var meta struct {
				Id uint `json:"id"`
			}
			if err := json.Unmarshal(data, &meta); err != nil {
				return err
			}
			id = meta.Id
			if object == "nodes" && jobRunning(id) {
				return errors.New("node_job_running")
			}
			if action != "new" && action != "edit" && !(object == "nodes" && (action == "applytemplate" || action == "selectinbounds" || action == "retry")) {
				return errors.New("unknown Nodes action")
			}
			if action == "new" && id != 0 {
				return errors.New("new remote records must not reuse supplied IDs")
			}
		}
		switch object {
		case "nodetemplates":
			if action == "del" {
				var template model.NodeTemplate
				if err := tx.First(&template, id).Error; err != nil {
					return err
				}
				if template.Kind == deploymentTemplate {
					return errors.New("edit_node_inbound_selection")
				}
				var members int64
				if err := tx.Model(&model.NodeTemplateMember{}).Where("inbound_id = ?", id).Count(&members).Error; err != nil {
					return err
				}
				if members > 0 {
					return errors.New("node_template_in_use")
				}
				var copies int64
				if err := tx.Model(&model.NodeTemplate{}).Where("parent_template_id = ?", id).Count(&copies).Error; err != nil {
					return err
				}
				if copies > 0 {
					return errors.New("template_is_copy_origin")
				}
				var used int64
				if err := tx.Model(&model.Node{}).Where("template_id = ?", id).Count(&used).Error; err != nil {
					return err
				}
				if used > 0 {
					return errors.New("node_template_in_use")
				}
				if err := tx.Delete(&model.NodeTemplate{}, id).Error; err != nil {
					return err
				}
				if err := tx.Where("template_id = ?", id).Delete(&model.NodeTemplateVersion{}).Error; err != nil {
					return err
				}
			} else {
				value := model.NodeTemplate{}
				if action == "edit" {
					if err := tx.First(&value, id).Error; err != nil {
						return err
					}
				}
				old := value
				old.Config = append(json.RawMessage(nil), value.Config...)
				old.Blueprints = append(json.RawMessage(nil), value.Blueprints...)
				old.Protocols = append(json.RawMessage(nil), value.Protocols...)
				if err := json.Unmarshal(data, &value); err != nil {
					return err
				}
				if old.Kind == deploymentTemplate {
					return errors.New("edit_node_inbound_selection")
				}
				if action == "new" && value.Kind != "" && value.Kind != inboundTemplate {
					return errors.New("invalid_node_template_kind")
				}
				if value.Kind == inboundTemplate || old.Kind == inboundTemplate {
					var request struct {
						Spec json.RawMessage
					}
					if err := json.Unmarshal(data, &request); err != nil || len(request.Spec) == 0 {
						return errors.New("one_inbound_per_template")
					}
				}
				if strings.TrimSpace(value.Name) == "" {
					return errors.New("node template needs a name")
				}
				value.ParentTemplateId = old.ParentTemplateId
				handled, err := saveVersionedTemplate(tx, &value, old, data)
				if err != nil {
					return err
				}
				if handled {
					id = value.Id
					break
				}
				var config map[string]json.RawMessage
				if json.Unmarshal(value.Config, &config) != nil || config == nil {
					return errors.New("node template config must be an object")
				}
				if err := normalizeBlueprints(&value, old); err != nil {
					return err
				}
				if err := validateSimpleTemplate(&value); err != nil {
					return err
				}
				if action == "edit" {
					if err := tx.Model(&model.Node{}).Where("template_id = ? AND (config IS NULL OR length(config) = 0)", id).Updates(map[string]interface{}{"config": old.Config, "template_base": old.Config}).Error; err != nil {
						return err
					}
				}
				if err := tx.Save(&value).Error; err != nil {
					return err
				}
				if err := appendTemplateVersion(tx, &value, old, nil); err != nil {
					return err
				}
				id = value.Id
			}
		case "nodes":
			value := model.Node{Enable: true}
			if action != "new" {
				if err := tx.First(&value, id).Error; err != nil {
					return err
				}
			}
			if action == "del" {
				if jobRunning(id) {
					return errors.New("node_job_running")
				}
				var activeJobs int64
				if err := tx.Model(&model.NodeJob{}).Where("node_id = ? AND state IN ?", id, []string{"queued", "running"}).Count(&activeJobs).Error; err != nil {
					return err
				}
				if activeJobs > 0 {
					return errors.New("node_job_running")
				}
				var resourceTask model.NodeTask
				if err := tx.Where("node_id = ? AND kind = ?", id, "resources").First(&resourceTask).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}
				if resourceTask.LeaseUntil > time.Now().Unix() {
					return errors.New("node_resource_job_running")
				}
				var installation model.NodeInstallation
				if err := tx.First(&installation, "node_id = ?", id).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}
				if len(installation.PreviousTarget) > 0 {
					return errors.New("old_server_retirement_pending")
				}
				if !disableConfirmed(value) {
					return errors.New("node_disable_pending_delete")
				}
				if !deleteRequest.DNSAlreadyRemoved {
					var owned int64
					if err := tx.Model(&model.NodeDNSRecord{}).Where("node_id = ? AND retired = ?", id, false).Count(&owned).Error; err != nil {
						return err
					}
					if owned > 0 {
						return errNodeDNSCleanupRequired
					}
				}
				var ids []uint
				if err := tx.Model(&model.NodeInbound{}).Where("node_id = ?", id).Pluck("id", &ids).Error; err != nil {
					return err
				}
				if len(ids) > 0 {
					if err := tx.Where("node_inbound_id in ?", ids).Delete(&model.ClientNodeInbound{}).Error; err != nil {
						return err
					}
				}
				if err := tx.Where("node_id = ?", id).Delete(&model.NodeInbound{}).Error; err != nil {
					return err
				}
				// No grants or control state may survive a logical node deletion.
				// A restored database can otherwise reuse the deleted numeric ID.
				for _, row := range []interface{}{&model.ClientNode{}, &model.NodeAccessState{}, &model.NodeTask{}, &model.NodeOverride{}, &model.NodeGeneratedMaterial{}, &model.NodeAssignmentMigration{}, &model.NodeInstallation{}, &model.NodeJob{}, &model.NodeDeployment{}, &model.NodePortReservation{}, &model.NodeDomainBinding{}, &model.NodeCertificateBinding{}, &model.NodeCertificateVersion{}, &model.NodeDNSRecord{}} {
					if err := tx.Where("node_id = ?", id).Delete(row).Error; err != nil {
						return err
					}
				}
				if err := tx.Delete(&model.Node{}, id).Error; err != nil {
					return err
				}
				if err := detachOrphanedPrivateDeployments(tx); err != nil {
					return err
				}
			} else if action == "retry" {
				if err := tx.Model(&value).Updates(map[string]interface{}{"desired_fingerprint": "", "rejected_revision": 0, "last_error": ""}).Error; err != nil {
					return err
				}
				if value.TemplateTargetVersion > 0 {
					if err := database.QueueNodeTasks(tx, []uint{id}, "structure"); err != nil {
						return err
					}
				}
			} else if action == "selectinbounds" {
				var request struct {
					Ids      []uint  `json:"inbound_template_ids"`
					Expected *uint64 `json:"expected_version"`
				}
				if err := json.Unmarshal(data, &request); err != nil {
					return err
				}
				if err := selectNodeInbounds(tx, &value, request.Ids, request.Expected); err != nil {
					return err
				}
			} else if action == "applytemplate" {
				var request struct {
					TemplateId     uint `json:"template_id"`
					ConfirmReplace bool `json:"confirm_replace"`
				}
				if err := json.Unmarshal(data, &request); err != nil {
					return err
				}
				var target model.NodeTemplate
				if err := tx.First(&target, request.TemplateId).Error; err != nil {
					return err
				}
				if target.Kind == inboundTemplate {
					return errors.New("edit_node_inbound_selection")
				}
				var applyErr error
				if target.SchemaVersion == 1 {
					applyErr = bindLiveTemplate(tx, &value, target, request.ConfirmReplace)
				} else if value.TemplateTargetVersion > 0 {
					applyErr = errors.New("live_template_cannot_use_legacy_copy")
				} else {
					applyErr = applyTemplate(tx, &value, request.TemplateId)
				}
				if err := applyErr; err != nil {
					return err
				}
			} else {
				var request struct {
					Name        *string         `json:"name"`
					Enable      *bool           `json:"enable"`
					Address     *string         `json:"address"`
					LinkAddress *string         `json:"linkaddress"`
					TemplateID  *uint           `json:"template_id"`
					Config      json.RawMessage `json:"config"`
					TLS         *ControlTLS     `json:"control_tls"`
				}
				previousAddress, previousCertificate, previousKey, previousCA := value.Address, value.ControlCertificate, value.ControlKey, value.ControlCA
				if err := json.Unmarshal(data, &request); err != nil {
					return err
				}
				if request.Name != nil {
					value.Name = *request.Name
				}
				if request.Enable != nil {
					value.Enable = *request.Enable
				}
				if request.Address != nil {
					value.Address = strings.TrimRight(*request.Address, "/")
				}
				if request.LinkAddress != nil {
					value.LinkAddress = *request.LinkAddress
				}
				targetTemplate := value.TemplateId
				if request.TemplateID != nil {
					targetTemplate = *request.TemplateID
				}
				if request.Config != nil {
					if value.TemplateTargetVersion > 0 {
						return errors.New("live_template_use_explicit_overrides")
					}
					if _, err := decodeObject(request.Config); err != nil {
						return err
					}
					value.Config = request.Config
				}
				if request.TLS != nil {
					value.ControlCA = request.TLS.CA
					value.ControlCertificate = request.TLS.Certificate
					value.ControlKey = request.TLS.Key
				}
				if previousAddress != value.Address || previousCertificate != value.ControlCertificate || previousKey != value.ControlKey || previousCA != value.ControlCA {
					value.LastSeen = 0
					value.LastError = ""
				}
				if strings.TrimSpace(value.Name) == "" {
					return errors.New("node needs a name")
				}
				if targetTemplate != 0 {
					var count int64
					if err := tx.Model(&model.NodeTemplate{}).Where("id = ?", targetTemplate).Count(&count).Error; err != nil {
						return err
					}
					if count != 1 {
						return errors.New("unknown node template")
					}
				}
				if err := validateControl(value); err != nil {
					return err
				}
				if err := tx.Save(&value).Error; err != nil {
					return err
				}
				if targetTemplate != 0 && (action == "new" || targetTemplate != value.TemplateId) {
					if err := applyTemplate(tx, &value, targetTemplate); err != nil {
						return err
					}
				} else if targetTemplate == 0 && value.TemplateId != 0 {
					if value.TemplateTargetVersion > 0 {
						return errors.New("live_template_use_private_copy")
					}
					if len(value.Config) == 0 {
						var prior model.NodeTemplate
						if err := tx.First(&prior, value.TemplateId).Error; err != nil {
							return err
						}
						value.Config = prior.Config
					}
					value.TemplateId = 0
					value.TemplateBase = nil
					if err := tx.Save(&value).Error; err != nil {
						return err
					}
					if err := tx.Model(&model.NodeInbound{}).Where("node_id = ?", value.Id).Updates(map[string]interface{}{"source_template_id": 0, "template_key": "", "template_base": nil}).Error; err != nil {
						return err
					}
				}
				id = value.Id
				if value.TemplateTargetVersion > 0 {
					if err := queueNodeStructure(tx, &value); err != nil {
						return err
					}
				}
			}
		case "nodeinbounds":
			value := model.NodeInbound{Enable: true}
			if action != "new" {
				if err := tx.First(&value, id).Error; err != nil {
					return err
				}
			}
			var inboundNodeID uint = value.NodeId
			if action == "new" {
				var request struct {
					NodeId uint `json:"node_id"`
				}
				if err := json.Unmarshal(data, &request); err != nil {
					return err
				}
				inboundNodeID = request.NodeId
			}
			var inboundNode model.Node
			if err := tx.First(&inboundNode, inboundNodeID).Error; err != nil {
				return err
			}
			if inboundNode.TemplateTargetVersion > 0 {
				return errors.New("live_template_owns_connections")
			}
			if action == "del" {
				if err := tx.Where("node_inbound_id = ?", id).Delete(&model.ClientNodeInbound{}).Error; err != nil {
					return err
				}
				if err := tx.Delete(&model.NodeInbound{}, id).Error; err != nil {
					return err
				}
			} else {
				previousNode := value.NodeId
				previousType, sourceTemplate, key, base := value.Type, value.SourceTemplateId, value.TemplateKey, value.TemplateBase
				if err := json.Unmarshal(data, &value); err != nil {
					return err
				}
				if action == "edit" && value.NodeId != previousNode {
					return errors.New("create a new inbound to move it to another node")
				}
				if action == "edit" && value.Type != previousType {
					return errors.New("create a new inbound to change its protocol")
				}
				value.SourceTemplateId, value.TemplateKey, value.TemplateBase = sourceTemplate, key, base
				var count int64
				if err := tx.Model(&model.Node{}).Where("id = ?", value.NodeId).Count(&count).Error; err != nil {
					return err
				}
				if count != 1 {
					return errors.New("unknown node")
				}
				if strings.TrimSpace(value.Tag) == "" {
					return errors.New("remote inbound needs a tag")
				}
				switch value.Type {
				case "vless", "tuic", "hysteria2":
				default:
					return errors.New("unsupported node protocol")
				}
				var options map[string]interface{}
				if json.Unmarshal(value.Options, &options) != nil || options == nil {
					return errors.New("invalid node inbound options")
				}
				port, ok := options["listen_port"].(float64)
				if !ok || port < 1 || port > 65535 || float64(int(port)) != port {
					return errors.New("invalid remote listen port")
				}
				delete(options, "users")
				delete(options, "type")
				delete(options, "tag")
				value.Options, _ = json.Marshal(options)
				if _, _, err := clientTLS(value); err != nil {
					return err
				}
				if err := tx.Save(&value).Error; err != nil {
					return err
				}
				id = value.Id
			}
		}
		// Do not put write-only control keys or server options in the audit entry.
		if action != "del" && (object == "nodes" || object == "nodeinbounds") {
			nodeID := id
			if object == "nodeinbounds" {
				var inbound model.NodeInbound
				if err := tx.First(&inbound, id).Error; err != nil {
					return err
				}
				nodeID = inbound.NodeId
			}
			var node model.Node
			if err := tx.First(&node, nodeID).Error; err != nil {
				return err
			}
			if node.TemplateTargetVersion == 0 {
				if _, err := Compile(tx, node); err != nil {
					return err
				}
			}
		}
		obj, _ := json.Marshal(map[string]uint{"id": id})
		if deleteRequest.DNSAlreadyRemoved {
			obj, _ = json.Marshal(deleteRequest)
		}
		return tx.Create(&model.Changes{DateTime: time.Now().Unix(), Actor: actor, Key: object, Action: action, Obj: obj}).Error
	})
}
