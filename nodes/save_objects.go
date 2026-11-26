package nodes

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"gorm.io/gorm"
)

func parseSaveIdentity(object, action string, data json.RawMessage) (uint, nodeDeleteRequest, error) {
	var id uint
	var deleteRequest nodeDeleteRequest
	if action == "del" {
		if object == "nodes" {
			var err error
			deleteRequest, err = parseNodeDelete(data)
			if err != nil {
				return id, deleteRequest, err
			}
			id = deleteRequest.Id
		} else if err := json.Unmarshal(data, &id); err != nil {
			return id, deleteRequest, err
		}
	} else {
		var meta struct {
			Id uint `json:"id"`
		}
		if err := json.Unmarshal(data, &meta); err != nil {
			return id, deleteRequest, err
		}
		id = meta.Id
		if object == "nodes" && jobRunning(id) {
			return id, deleteRequest, errors.New("node_job_running")
		}
		if action != "new" && action != "edit" && !(object == "nodes" && (action == "applytemplate" || action == "selectinbounds" || action == "retry")) {
			return id, deleteRequest, errors.New("unknown Nodes action")
		}
		if action == "new" && id != 0 {
			return id, deleteRequest, errors.New("new remote records must not reuse supplied IDs")
		}
	}
	return id, deleteRequest, nil
}
func saveTemplateObject(tx *gorm.DB, action string, data json.RawMessage, id uint) (uint, error) {
	if action == "del" {
		return id, deleteTemplateObject(tx, id)
	}
	value := model.NodeTemplate{}
	if action == "edit" {
		if err := tx.First(&value, id).Error; err != nil {
			return id, err
		}
	}
	old := value
	old.Config = append(json.RawMessage(nil), value.Config...)
	old.Blueprints = append(json.RawMessage(nil), value.Blueprints...)
	old.Protocols = append(json.RawMessage(nil), value.Protocols...)
	if err := json.Unmarshal(data, &value); err != nil {
		return id, err
	}
	if old.Kind == deploymentTemplate {
		return id, errors.New("edit_node_inbound_selection")
	}
	if action == "new" && value.Kind != "" && value.Kind != inboundTemplate {
		return id, errors.New("invalid_node_template_kind")
	}
	if value.Kind == inboundTemplate || old.Kind == inboundTemplate {
		var request struct {
			Spec json.RawMessage
		}
		if err := json.Unmarshal(data, &request); err != nil || len(request.Spec) == 0 {
			return id, errors.New("one_inbound_per_template")
		}
	}
	if strings.TrimSpace(value.Name) == "" {
		return id, errors.New("node template needs a name")
	}
	value.ParentTemplateId = old.ParentTemplateId
	handled, err := saveVersionedTemplate(tx, &value, old, data)
	if err != nil {
		return id, err
	}
	if handled {
		id = value.Id
		return id, nil
	}
	var config map[string]json.RawMessage
	if json.Unmarshal(value.Config, &config) != nil || config == nil {
		return id, errors.New("node template config must be an object")
	}
	if err := normalizeBlueprints(&value, old); err != nil {
		return id, err
	}
	if err := validateSimpleTemplate(&value); err != nil {
		return id, err
	}
	if action == "edit" {
		if err := tx.Model(&model.Node{}).Where("template_id = ? AND (config IS NULL OR length(config) = 0)", id).Updates(map[string]interface{}{"config": old.Config, "template_base": old.Config}).Error; err != nil {
			return id, err
		}
	}
	if err := tx.Save(&value).Error; err != nil {
		return id, err
	}
	if err := appendTemplateVersion(tx, &value, old, nil); err != nil {
		return id, err
	}
	id = value.Id
	return id, nil
}

func deleteTemplateObject(tx *gorm.DB, id uint) error {
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
	if err := tx.Model(&model.Node{}).Where(whereTemplateID, id).Count(&used).Error; err != nil {
		return err
	}
	if used > 0 {
		return errors.New("node_template_in_use")
	}
	if err := tx.Delete(&model.NodeTemplate{}, id).Error; err != nil {
		return err
	}
	if err := tx.Where(whereTemplateID, id).Delete(&model.NodeTemplateVersion{}).Error; err != nil {
		return err
	}
	return nil
}
func saveServerObject(tx *gorm.DB, action string, data json.RawMessage, id uint, deleteRequest nodeDeleteRequest) (uint, error) {
	value := model.Node{Enable: true}
	if action != "new" {
		if err := tx.First(&value, id).Error; err != nil {
			return id, err
		}
	}
	switch action {
	case "del":
		return id, deleteNodeObject(tx, value, deleteRequest)
	case "retry":
		return id, retryNodeObject(tx, value)
	case "selectinbounds":
		return id, selectNodeObject(tx, value, data)
	case "applytemplate":
		return id, applyNodeObjectTemplate(tx, value, data)
	default:
		return editNodeObject(tx, value, action, data)
	}
}
func deleteNodeObject(tx *gorm.DB, value model.Node, deleteRequest nodeDeleteRequest) error {
	id := value.Id
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
	if err := tx.First(&installation, whereNodeID, id).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	if len(installation.PreviousTarget) > 0 {
		return errors.New("old_server_retirement_pending")
	}
	if !disableConfirmed(value) && (value.Enable || !deleteRequest.ServerAlreadyStopped) {
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
	if err := tx.Model(&model.NodeInbound{}).Where(whereNodeID, id).Pluck("id", &ids).Error; err != nil {
		return err
	}
	if len(ids) > 0 {
		if err := tx.Where("node_inbound_id in ?", ids).Delete(&model.ClientNodeInbound{}).Error; err != nil {
			return err
		}
	}
	if err := tx.Where(whereNodeID, id).Delete(&model.NodeInbound{}).Error; err != nil {
		return err
	}
	// No grants or control state may survive a logical node deletion.
	// A restored database can otherwise reuse the deleted numeric ID.
	for _, row := range []interface{}{&model.ClientNode{}, &model.NodeAccessState{}, &model.NodeTask{}, &model.NodeOverride{}, &model.NodeGeneratedMaterial{}, &model.NodeAssignmentMigration{}, &model.NodeInstallation{}, &model.NodeJob{}, &model.NodeDeployment{}, &model.NodePortReservation{}, &model.NodeDomainBinding{}, &model.NodeCertificateBinding{}, &model.NodeCertificateVersion{}, &model.NodeDNSRecord{}} {
		if err := tx.Where(whereNodeID, id).Delete(row).Error; err != nil {
			return err
		}
	}
	if err := tx.Delete(&model.Node{}, id).Error; err != nil {
		return err
	}
	if err := tx.Where(whereNodeID, id).Delete(&model.NodeClientTraffic{}).Error; err != nil {
		return err
	}
	if err := detachOrphanedPrivateDeployments(tx); err != nil {
		return err
	}

	return nil
}

func retryNodeObject(tx *gorm.DB, value model.Node) error {
	id := value.Id
	if err := tx.Model(&value).Updates(map[string]interface{}{"desired_fingerprint": "", "rejected_revision": 0, "last_error": ""}).Error; err != nil {
		return err
	}
	if value.TemplateTargetVersion > 0 {
		if err := database.QueueNodeTasks(tx, []uint{id}, "structure"); err != nil {
			return err
		}
	}
	if value.AgentProtocol == 2 {
		if err := database.QueueNodeTasks(tx, []uint{id}, "access"); err != nil {
			return err
		}
	}

	return nil
}

func selectNodeObject(tx *gorm.DB, value model.Node, data json.RawMessage) error {
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

	return nil
}

func applyNodeObjectTemplate(tx *gorm.DB, value model.Node, data json.RawMessage) error {
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

	return nil
}

func editNodeObject(tx *gorm.DB, value model.Node, action string, data json.RawMessage) (uint, error) {
	id := value.Id
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
		return id, err
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
			return id, errors.New("live_template_use_explicit_overrides")
		}
		if _, err := decodeObject(request.Config); err != nil {
			return id, err
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
		return id, errors.New("node needs a name")
	}
	if targetTemplate != 0 {
		var count int64
		if err := tx.Model(&model.NodeTemplate{}).Where("id = ?", targetTemplate).Count(&count).Error; err != nil {
			return id, err
		}
		if count != 1 {
			return id, errors.New("unknown node template")
		}
	}
	if err := validateControl(value); err != nil {
		return id, err
	}
	if err := tx.Save(&value).Error; err != nil {
		return id, err
	}
	if targetTemplate != 0 && (action == "new" || targetTemplate != value.TemplateId) {
		if err := applyTemplate(tx, &value, targetTemplate); err != nil {
			return id, err
		}
	} else if targetTemplate == 0 && value.TemplateId != 0 {
		if value.TemplateTargetVersion > 0 {
			return id, errors.New("live_template_use_private_copy")
		}
		if len(value.Config) == 0 {
			var prior model.NodeTemplate
			if err := tx.First(&prior, value.TemplateId).Error; err != nil {
				return id, err
			}
			value.Config = prior.Config
		}
		value.TemplateId = 0
		value.TemplateBase = nil
		if err := tx.Save(&value).Error; err != nil {
			return id, err
		}
		if err := tx.Model(&model.NodeInbound{}).Where(whereNodeID, value.Id).Updates(map[string]interface{}{"source_template_id": 0, "template_key": "", "template_base": nil}).Error; err != nil {
			return id, err
		}
	}
	id = value.Id
	if value.TemplateTargetVersion > 0 {
		if err := queueNodeStructure(tx, &value); err != nil {
			return id, err
		}
	}
	return id, nil
}
func saveInboundObject(tx *gorm.DB, action string, data json.RawMessage, id uint) (uint, error) {
	value := model.NodeInbound{Enable: true}
	if action != "new" {
		if err := tx.First(&value, id).Error; err != nil {
			return id, err
		}
	}
	var inboundNodeID uint = value.NodeId
	if action == "new" {
		var request struct {
			NodeId uint `json:"node_id"`
		}
		if err := json.Unmarshal(data, &request); err != nil {
			return id, err
		}
		inboundNodeID = request.NodeId
	}
	var inboundNode model.Node
	if err := tx.First(&inboundNode, inboundNodeID).Error; err != nil {
		return id, err
	}
	if inboundNode.TemplateTargetVersion > 0 {
		return id, errors.New("live_template_owns_connections")
	}
	if action == "del" {
		if err := tx.Where("node_inbound_id = ?", id).Delete(&model.ClientNodeInbound{}).Error; err != nil {
			return id, err
		}
		if err := tx.Delete(&model.NodeInbound{}, id).Error; err != nil {
			return id, err
		}
	} else {
		previousNode := value.NodeId
		previousType, sourceTemplate, key, base := value.Type, value.SourceTemplateId, value.TemplateKey, value.TemplateBase
		if err := json.Unmarshal(data, &value); err != nil {
			return id, err
		}
		if action == "edit" && value.NodeId != previousNode {
			return id, errors.New("create a new inbound to move it to another node")
		}
		if action == "edit" && value.Type != previousType {
			return id, errors.New("create a new inbound to change its protocol")
		}
		value.SourceTemplateId, value.TemplateKey, value.TemplateBase = sourceTemplate, key, base
		var count int64
		if err := tx.Model(&model.Node{}).Where("id = ?", value.NodeId).Count(&count).Error; err != nil {
			return id, err
		}
		if count != 1 {
			return id, errors.New("unknown node")
		}
		if strings.TrimSpace(value.Tag) == "" {
			return id, errors.New("remote inbound needs a tag")
		}
		switch value.Type {
		case "vless", "tuic", "hysteria2":
		default:
			return id, errors.New("unsupported node protocol")
		}
		var options map[string]interface{}
		if json.Unmarshal(value.Options, &options) != nil || options == nil {
			return id, errors.New("invalid node inbound options")
		}
		port, ok := options["listen_port"].(float64)
		if !ok || port < 1 || port > 65535 || float64(int(port)) != port {
			return id, errors.New("invalid remote listen port")
		}
		delete(options, "users")
		delete(options, "type")
		delete(options, "tag")
		value.Options, _ = json.Marshal(options)
		if _, _, err := clientTLS(value); err != nil {
			return id, err
		}
		if err := tx.Save(&value).Error; err != nil {
			return id, err
		}
		id = value.Id
	}
	return id, nil
}

func finishNodeSave(tx *gorm.DB, object, action string, id uint, deleteRequest nodeDeleteRequest, actor string) error {
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
	if deleteRequest.DNSAlreadyRemoved || deleteRequest.ServerAlreadyStopped {
		obj, _ = json.Marshal(deleteRequest)
	}
	return tx.Create(&model.Changes{DateTime: time.Now().Unix(), Actor: actor, Key: object, Action: action, Obj: obj}).Error
}
