package nodes

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/alireza0/s-ui/database/model"
	"gorm.io/gorm"
)

const (
	inboundTemplate    = "inbound"
	deploymentTemplate = "deployment"
)

// The catalog edits one inbound at a time. Each deployment still uses the
// existing immutable template version, so agents and subscriptions have one
// atomic configuration to acknowledge.
func UpgradeInboundCatalog(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var templates []model.NodeTemplate
		if err := tx.Where("schema_version = 1 AND kind = ''").Order("id").Find(&templates).Error; err != nil {
			return err
		}
		for _, template := range templates {
			if template.Scope == "private" {
				var used int64
				if err := tx.Model(&model.Node{}).Where("template_id = ?", template.Id).Count(&used).Error; err != nil {
					return err
				}
				if used == 0 {
					// Preserve the old private deployment history without making
					// catalog entries that its owner cannot currently use.
					if err := tx.Model(&template).Update("kind", deploymentTemplate).Error; err != nil {
						return err
					}
					continue
				}
			}
			if err := splitDeploymentTemplate(tx, template); err != nil {
				return err
			}
		}
		return detachOrphanedPrivateDeployments(tx)
	})
}

// A private deployment with neither an owner nor a node using it is historical.
// Keep its saved versions and lineage, but release its current catalog links.
func detachOrphanedPrivateDeployments(tx *gorm.DB) error {
	orphaned := tx.Model(&model.NodeTemplate{}).Select("id").
		Where("kind = ? AND scope = ? AND owner_node_id > 0", deploymentTemplate, "private").
		Where(`NOT EXISTS (
			SELECT 1 FROM nodes AS n
			WHERE n.id = node_templates.owner_node_id OR n.template_id = node_templates.id
		)`)
	return tx.Where("template_id IN (?)", orphaned).Delete(&model.NodeTemplateMember{}).Error
}

func templateSpec(tx *gorm.DB, template model.NodeTemplate) (TemplateSpec, error) {
	return liveVersion(tx, model.Node{TemplateId: template.Id, TemplateTargetVersion: template.Version})
}

func splitDeploymentTemplate(tx *gorm.DB, template model.NodeTemplate) error {
	spec, err := templateSpec(tx, template)
	if err != nil {
		return err
	}
	for position, entry := range spec.Entries {
		inbound := model.NodeTemplate{
			Name: entry.Name, Kind: inboundTemplate, Protocol: entry.Protocol,
			Scope: template.Scope, OwnerNodeId: template.OwnerNodeId, SchemaVersion: 1,
			Config: json.RawMessage("{}"), Blueprints: json.RawMessage("[]"), Protocols: json.RawMessage("[]"),
		}
		if err := tx.Create(&inbound).Error; err != nil {
			return err
		}
		payload, err := json.Marshal(TemplateSpec{SchemaVersion: 1, Config: json.RawMessage("{}"), Entries: []SpecEntry{entry}})
		if err != nil {
			return err
		}
		if err := appendTemplateVersion(tx, &inbound, model.NodeTemplate{}, payload); err != nil {
			return err
		}
		if err := tx.Create(&model.NodeTemplateMember{TemplateId: template.Id, InboundId: inbound.Id, Position: position}).Error; err != nil {
			return err
		}
	}
	// Keep the template identity, versions and connection keys from the
	// installed database. Migration alone need not queue a deployment.
	return tx.Model(&template).Update("kind", deploymentTemplate).Error
}

func catalogMembers(tx *gorm.DB, templateID uint) ([]uint, error) {
	var ids []uint
	err := tx.Model(&model.NodeTemplateMember{}).Where("template_id = ?", templateID).Order("position").Pluck("inbound_id", &ids).Error
	return ids, err
}

func selectedInboundEntries(tx *gorm.DB, ids []uint, owner uint) ([]SpecEntry, error) {
	if len(ids) == 0 || len(ids) > 32 {
		return nil, errors.New("choose_node_inbound_templates")
	}
	entries := make([]SpecEntry, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		var template model.NodeTemplate
		if err := tx.First(&template, "id = ? AND kind = ?", id, inboundTemplate).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, errors.New("node_inbound_template_not_found")
			}
			return nil, err
		}
		if template.Scope == "private" && template.OwnerNodeId != owner {
			return nil, errors.New("private_template_belongs_to_another_node")
		}
		spec, err := templateSpec(tx, template)
		if err != nil {
			return nil, err
		}
		if len(spec.Entries) != 1 {
			return nil, errors.New("one_inbound_per_template")
		}
		entry := spec.Entries[0]
		if seen[entry.Key] {
			return nil, errors.New("duplicate_node_inbound_template")
		}
		seen[entry.Key] = true
		entries = append(entries, entry)
	}
	return entries, nil
}

func appendDeploymentSpec(tx *gorm.DB, template *model.NodeTemplate, spec TemplateSpec) error {
	body, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	spec, err = NormalizeSpec(body, nil)
	if err != nil {
		return err
	}
	body, err = json.Marshal(spec)
	if err != nil {
		return err
	}
	return appendTemplateVersion(tx, template, *template, body)
}

func createDeploymentTemplate(tx *gorm.DB, node model.Node) (model.NodeTemplate, error) {
	template := model.NodeTemplate{Name: node.Name, SchemaVersion: 1, Kind: deploymentTemplate, Scope: "private", OwnerNodeId: node.Id, ParentTemplateId: node.TemplateId}
	err := tx.Create(&template).Error
	return template, err
}

func writeCatalogSelection(tx *gorm.DB, template *model.NodeTemplate, ids []uint, spec TemplateSpec) error {
	if err := tx.Where("template_id = ?", template.Id).Delete(&model.NodeTemplateMember{}).Error; err != nil {
		return err
	}
	for position, id := range ids {
		if err := tx.Create(&model.NodeTemplateMember{TemplateId: template.Id, InboundId: id, Position: position}).Error; err != nil {
			return err
		}
	}
	return appendDeploymentSpec(tx, template, spec)
}

func selectNodeInbounds(tx *gorm.DB, node *model.Node, ids []uint, expected *uint64) error {
	if node.TemplateTargetVersion == 0 || node.AgentProtocol != 2 || node.AssignmentMode != model.NodeAssignmentWhole {
		return errors.New("live_template_requires_converted_v2_node")
	}
	if expected == nil || node.SettingsVersion != *expected {
		return errors.New("node_settings_version_conflict")
	}
	var template model.NodeTemplate
	if err := tx.First(&template, node.TemplateId).Error; err != nil {
		return err
	}
	old, err := catalogMembers(tx, template.Id)
	if err != nil {
		return err
	}
	if slices.Equal(old, ids) && len(ids) > 0 {
		return nil
	}
	entries, err := selectedInboundEntries(tx, ids, node.Id)
	if err != nil {
		return err
	}
	spec, err := liveVersion(tx, *node)
	if err != nil {
		return err
	}
	spec.Entries = entries
	if template.Kind != deploymentTemplate || template.Scope != "private" || template.OwnerNodeId != node.Id {
		template, err = createDeploymentTemplate(tx, *node)
		if err != nil {
			return err
		}
	}
	if err := writeCatalogSelection(tx, &template, ids, spec); err != nil {
		return err
	}
	node.TemplateId = template.Id
	node.TemplateTargetVersion = template.Version
	if err := tx.Model(node).Updates(map[string]interface{}{"template_id": template.Id, "template_target_version": template.Version}).Error; err != nil {
		return err
	}
	return queueNodeStructure(tx, node)
}

func refreshCatalogDeployments(tx *gorm.DB, inboundID uint) error {
	var groups []uint
	if err := tx.Model(&model.NodeTemplateMember{}).Where("inbound_id = ?", inboundID).Pluck("template_id", &groups).Error; err != nil {
		return err
	}
	for _, id := range groups {
		var group model.NodeTemplate
		if err := tx.First(&group, id).Error; err != nil {
			return err
		}
		var nodes []model.Node
		if err := tx.Where("template_id = ?", id).Find(&nodes).Error; err != nil {
			return err
		}
		for _, node := range nodes {
			if jobRunning(node.Id) {
				return errors.New("node_job_running")
			}
		}
		ids, err := catalogMembers(tx, id)
		if err != nil {
			return err
		}
		entries, err := selectedInboundEntries(tx, ids, group.OwnerNodeId)
		if err != nil {
			return err
		}
		spec, err := templateSpec(tx, group)
		if err != nil {
			return err
		}
		spec.Entries = entries
		if err := appendDeploymentSpec(tx, &group, spec); err != nil {
			return err
		}
	}
	return nil
}
