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

func queueLiveTemplate(tx *gorm.DB, template model.NodeTemplate) error {
	var ids []uint
	if err := tx.Model(&model.Node{}).Where("template_id = ? AND template_target_version > 0", template.Id).Pluck("id", &ids).Error; err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	if err := tx.Model(&model.Node{}).Where("id IN ?", ids).Update("template_target_version", template.Version).Error; err != nil {
		return err
	}
	return database.QueueNodeTasks(tx, ids, "structure")
}

func queueNodeStructure(tx *gorm.DB, node *model.Node) error {
	node.SettingsVersion++
	if err := tx.Model(node).Update("settings_version", node.SettingsVersion).Error; err != nil {
		return err
	}
	return database.QueueNodeTasks(tx, []uint{node.Id}, "structure")
}

func templateRoot(tx *gorm.DB, id uint) (uint, error) {
	seen := map[uint]bool{}
	for len(seen) < 128 {
		if seen[id] {
			return 0, errors.New("invalid_template_lineage")
		}
		seen[id] = true
		var template model.NodeTemplate
		if err := tx.First(&template, id).Error; err != nil {
			return 0, err
		}
		if template.ParentTemplateId == 0 {
			return id, nil
		}
		id = template.ParentTemplateId
	}
	return 0, errors.New("invalid_template_lineage")
}

func bindLiveTemplate(tx *gorm.DB, node *model.Node, template model.NodeTemplate, replace bool) error {
	if node.AgentProtocol != 2 || node.AssignmentMode != model.NodeAssignmentWhole {
		return errors.New("live_template_requires_converted_v2_node")
	}
	if template.Scope == "private" && template.OwnerNodeId != node.Id {
		return errors.New("private_template_belongs_to_another_node")
	}
	if node.TemplateId != template.Id || node.TemplateTargetVersion == 0 {
		var count int64
		if err := tx.Model(&model.NodeInbound{}).Where(whereNodeID, node.Id).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 && !replace {
			return errors.New("template_replacement_confirmation_required")
		}
		if count > 0 && node.TemplateTargetVersion > 0 && node.TemplateId != template.Id {
			var previous model.NodeTemplate
			if err := tx.First(&previous, node.TemplateId).Error; err != nil {
				return err
			}
			if err := validateLiveTemplateLineage(tx, node, previous, template); err != nil {
				return err
			}
		}
	}
	node.TemplateId, node.TemplateTargetVersion = template.Id, template.Version
	if err := tx.Save(node).Error; err != nil {
		return err
	}
	return queueNodeStructure(tx, node)
}

func liveVersion(tx *gorm.DB, node model.Node) (TemplateSpec, error) {
	var version model.NodeTemplateVersion
	var spec TemplateSpec
	if err := tx.First(&version, whereTemplateVersion, node.TemplateId, node.TemplateTargetVersion).Error; err != nil {
		return spec, err
	}
	if version.SchemaVersion != 1 || versionDigest(version.Payload) != version.Digest {
		return spec, errors.New("invalid_live_template_version")
	}
	return NormalizeSpec(version.Payload, nil)
}

type liveActionRequest struct {
	Id              uint           `json:"id"`
	Name            string         `json:"name"`
	Version         uint64         `json:"version"`
	ExpectedVersion uint64         `json:"expected_version"`
	Overrides       []SpecOverride `json:"overrides"`
}

func saveLiveAction(tx *gorm.DB, object, action string, data json.RawMessage, actor string) error {
	var request liveActionRequest
	if err := decodeJSON(data, &request, true); err != nil {
		return err
	}
	if request.Id == 0 {
		return errors.New("invalid_live_template_action")
	}
	if action == "restoreversion" && object == "nodetemplates" {
		if err := restoreLiveTemplateVersion(tx, request); err != nil {
			return err
		}
	} else if object == "nodes" {
		if err := saveLiveNodeAction(tx, action, request); err != nil {
			return err
		}
	} else {
		return errors.New("invalid_live_template_action")
	}
	obj, _ := json.Marshal(map[string]uint{"id": request.Id})
	return tx.Create(&model.Changes{DateTime: time.Now().Unix(), Actor: actor, Key: object, Action: action, Obj: obj}).Error
}

func validateLiveTemplateLineage(tx *gorm.DB, node *model.Node, previous, template model.NodeTemplate) error {
	previousRoot, err := templateRoot(tx, previous.Id)
	if err != nil {
		return err
	}
	nextRoot, err := templateRoot(tx, template.Id)
	if err != nil {
		return err
	}
	if previousRoot != nextRoot {
		var version model.NodeTemplateVersion
		if err := tx.First(&version, whereTemplateVersion, template.Id, template.Version).Error; err != nil {
			return err
		}
		var target TemplateSpec
		if json.Unmarshal(version.Payload, &target) != nil {
			return errors.New("invalid_live_template_version")
		}
		for _, entry := range target.Entries {
			var same int64
			if err := tx.Model(&model.NodeInbound{}).Where("node_id = ? AND connection_key = ?", node.Id, entry.Key).Count(&same).Error; err != nil {
				return err
			}
			if same > 0 {
				return errors.New("unrelated_template_connection_mapping_required")
			}
		}
	}
	return nil
}

func restoreLiveTemplateVersion(tx *gorm.DB, request liveActionRequest) error {
	var template model.NodeTemplate
	var version model.NodeTemplateVersion
	if err := tx.First(&template, request.Id).Error; err != nil {
		return err
	}
	if template.Kind == deploymentTemplate {
		return errors.New("edit_node_inbound_selection")
	}
	if err := tx.First(&version, whereTemplateVersion, request.Id, request.Version).Error; err != nil {
		return err
	}
	if version.SchemaVersion != 1 {
		return errors.New("legacy_version_cannot_be_live_restored")
	}
	body, _ := json.Marshal(map[string]interface{}{"spec": version.Payload, "expected_version": request.ExpectedVersion})
	if _, err := saveVersionedTemplate(tx, &template, template, body); err != nil {
		return err
	}
	return nil
}

func saveLiveNodeAction(tx *gorm.DB, action string, request liveActionRequest) error {
	var node model.Node
	if err := tx.First(&node, request.Id).Error; err != nil {
		return err
	}
	if node.TemplateTargetVersion == 0 {
		return errors.New("node_has_no_live_template")
	}
	if node.SettingsVersion != request.ExpectedVersion {
		return errors.New("node_settings_version_conflict")
	}
	spec, err := liveVersion(tx, node)
	if err != nil {
		return err
	}
	switch action {
	case "setoverrides":
		if err := replaceLiveOverrides(tx, node.Id, spec, request.Overrides); err != nil {
			return err
		}
	case "privatecopy", "sharedcopy":
		if err := copyLiveNodeTemplate(tx, &node, spec, action, request.Name); err != nil {
			return err
		}
	default:
		return errors.New("invalid_live_template_action")
	}
	if err := queueNodeStructure(tx, &node); err != nil {
		return err
	}
	return nil
}

func replaceLiveOverrides(tx *gorm.DB, id uint, spec TemplateSpec, overrides []SpecOverride) error {
	if _, err := validateSpecOverrides(spec, overrides); err != nil {
		return err
	}
	// Archived records from removed keys do not become active implicitly.
	if err := tx.Where("node_id = ? AND archived = ?", id, false).Delete(&model.NodeOverride{}).Error; err != nil {
		return err
	}
	for _, override := range overrides {
		body, _ := json.Marshal(override.Source)
		row := model.NodeOverride{NodeId: id, ConnectionKey: override.ConnectionKey, Path: override.Path, Operation: override.Operation, Source: body}
		if err := tx.Save(&row).Error; err != nil {
			return err
		}
	}
	return nil
}

func copyLiveNodeTemplate(tx *gorm.DB, node *model.Node, spec TemplateSpec, action, name string) error {
	var current model.NodeTemplate
	if err := tx.First(&current, node.TemplateId).Error; err != nil {
		return err
	}
	if current.Kind == deploymentTemplate {
		return errors.New("edit_node_inbound_selection")
	}
	if strings.TrimSpace(name) == "" {
		return errors.New("private_template_needs_name")
	}
	draft := model.NodeTemplate{Name: name, Scope: "private", OwnerNodeId: node.Id, ParentTemplateId: node.TemplateId}
	if action == "sharedcopy" {
		draft.Scope = "shared"
		draft.OwnerNodeId = 0
	}
	body, _ := json.Marshal(map[string]interface{}{"spec": spec})
	if _, err := saveVersionedTemplate(tx, &draft, model.NodeTemplate{}, body); err != nil {
		return err
	}
	node.TemplateId, node.TemplateTargetVersion = draft.Id, draft.Version
	if err := tx.Save(node).Error; err != nil {
		return err
	}
	return nil
}
