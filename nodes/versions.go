package nodes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"gorm.io/gorm"
)

func versionDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func appendTemplateVersion(tx *gorm.DB, value *model.NodeTemplate, old model.NodeTemplate, spec json.RawMessage) error {
	legacy := func(v model.NodeTemplate) (json.RawMessage, error) {
		body, err := json.Marshal(struct {
			Config     json.RawMessage `json:"config"`
			Blueprints json.RawMessage `json:"blueprints"`
			Protocols  json.RawMessage `json:"protocols"`
		}{v.Config, v.Blueprints, v.Protocols})
		return body, err
	}
	write := func(version uint64, schema int, payload json.RawMessage) error {
		return tx.Create(&model.NodeTemplateVersion{TemplateId: value.Id, Version: version, SchemaVersion: schema, Digest: versionDigest(payload), Payload: payload, Created: time.Now().Unix()}).Error
	}
	current := old.Version
	if old.Id != 0 && current == 0 {
		current = 1
		baseline, err := legacy(old)
		if err != nil {
			return err
		}
		if err := write(current, 0, baseline); err != nil {
			return err
		}
	}
	payload := spec
	if value.SchemaVersion == 0 {
		var err error
		payload, err = legacy(*value)
		if err != nil {
			return err
		}
	}
	if current > 0 {
		var previous model.NodeTemplateVersion
		if err := tx.First(&previous, whereTemplateVersion, value.Id, current).Error; err != nil {
			return err
		}
		if previous.SchemaVersion == value.SchemaVersion && previous.Digest == versionDigest(payload) {
			value.Version = current
			return tx.Model(value).Update("version", current).Error
		}
	}
	current++
	if err := write(current, value.SchemaVersion, payload); err != nil {
		return err
	}
	value.Version = current
	if err := tx.Model(value).Updates(map[string]interface{}{"version": current, "schema_version": value.SchemaVersion}).Error; err != nil {
		return err
	}
	if value.SchemaVersion == 1 {
		if value.Kind == inboundTemplate {
			return refreshCatalogDeployments(tx, value.Id)
		}
		return queueLiveTemplate(tx, *value)
	}
	return nil
}

func saveVersionedTemplate(tx *gorm.DB, value *model.NodeTemplate, old model.NodeTemplate, data json.RawMessage) (bool, error) {
	var request struct {
		Spec            json.RawMessage `json:"spec"`
		ExpectedVersion *uint64         `json:"expected_version"`
	}
	if err := json.Unmarshal(data, &request); err != nil {
		return false, err
	}
	if request.ExpectedVersion != nil && *request.ExpectedVersion != old.Version {
		return false, errors.New("template_version_conflict")
	}
	if len(request.Spec) == 0 {
		if old.SchemaVersion == 1 {
			return false, errors.New("template_requires_versioned_editor")
		}
		value.Version = old.Version
		value.SchemaVersion = 0
		return false, nil
	}
	if old.Id != 0 && request.ExpectedVersion == nil {
		return false, errors.New("expected_template_version_required")
	}
	// A retired key keeps its protocol identity even after a version in which
	// the entry is absent. Restoring history must not reuse a VLESS key for TUIC.
	prior, err := priorTemplateProtocols(tx, old)
	if err != nil {
		return false, err
	}
	spec, err := NormalizeSpec(request.Spec, prior)
	if err != nil {
		return false, err
	}
	for i := range spec.Entries {
		if err := validateTLSProfile(tx, spec.Entries[i]); err != nil {
			return false, err
		}
		if err := sealRealmDraft(&spec.Entries[i]); err != nil {
			return false, err
		}
	}
	if err := updateInboundTemplateIdentity(tx, value, old, spec); err != nil {
		return false, err
	}
	value.SchemaVersion = 1
	value.Version = old.Version
	if err := updateTemplateScope(tx, value, old); err != nil {
		return false, err
	}
	// Old materialized nodes keep their exact base until the controlled rollout.
	if old.Id != 0 {
		value.Config = old.Config
		value.Blueprints = old.Blueprints
		value.Protocols = old.Protocols
	} else {
		value.Config = json.RawMessage(`{}`)
		value.Blueprints = json.RawMessage(`[]`)
		value.Protocols = json.RawMessage(`[]`)
	}
	if err := tx.Save(value).Error; err != nil {
		return false, err
	}
	payload, err := json.Marshal(spec)
	if err != nil {
		return false, err
	}
	return true, appendTemplateVersion(tx, value, old, payload)
}

func TemplateHistory(id uint) ([]model.NodeTemplateVersion, error) {
	versions := []model.NodeTemplateVersion{}
	err := database.GetDB().Order("version").Where(whereTemplateID, id).Find(&versions).Error
	return versions, err
}

type TemplateVersionView struct {
	TemplateId    uint            `json:"template_id"`
	Version       uint64          `json:"version"`
	SchemaVersion int             `json:"schema_version"`
	Digest        string          `json:"digest"`
	Spec          json.RawMessage `json:"spec,omitempty"`
}

func ReadTemplateVersion(id uint, version uint64) (TemplateVersionView, error) {
	var view TemplateVersionView
	if version == 0 {
		var template model.NodeTemplate
		if err := database.GetDB().First(&template, id).Error; err != nil {
			return view, err
		}
		version = template.Version
	}
	var row model.NodeTemplateVersion
	if err := database.GetDB().First(&row, whereTemplateVersion, id, version).Error; err != nil {
		return view, err
	}
	view = TemplateVersionView{TemplateId: id, Version: row.Version, SchemaVersion: row.SchemaVersion, Digest: row.Digest}
	if row.SchemaVersion == 1 {
		view.Spec = append(json.RawMessage(nil), row.Payload...)
	}
	return view, nil
}

func priorTemplateProtocols(tx *gorm.DB, old model.NodeTemplate) (*TemplateSpec, error) {
	prior := &TemplateSpec{}
	if old.Id != 0 {
		var history []model.NodeTemplateVersion
		if err := tx.Where(whereTemplateID, old.Id).Order("version").Find(&history).Error; err != nil {
			return nil, err
		}
		for _, version := range history {
			if err := appendPriorTemplateProtocols(prior, version); err != nil {
				return nil, err
			}
		}
		if old.Version == 0 {
			var previous []Blueprint
			if len(old.Blueprints) > 0 {
				if err := json.Unmarshal(old.Blueprints, &previous); err != nil {
					return nil, err
				}
			}
			for _, entry := range previous {
				prior.Entries = append(prior.Entries, SpecEntry{Key: entry.Key, Protocol: entry.Type})
			}
		}
	}
	return prior, nil
}

func appendPriorTemplateProtocols(prior *TemplateSpec, version model.NodeTemplateVersion) error {
	if version.SchemaVersion == 1 {
		var previous TemplateSpec
		if err := json.Unmarshal(version.Payload, &previous); err != nil {
			return err
		}
		prior.Entries = append(prior.Entries, previous.Entries...)
	} else {
		var previous struct {
			Blueprints []Blueprint `json:"blueprints"`
		}
		if err := json.Unmarshal(version.Payload, &previous); err != nil {
			return err
		}
		for _, entry := range previous.Blueprints {
			prior.Entries = append(prior.Entries, SpecEntry{Key: entry.Key, Protocol: entry.Type})
		}
	}
	return nil
}

func updateInboundTemplateIdentity(tx *gorm.DB, value *model.NodeTemplate, old model.NodeTemplate, spec TemplateSpec) error {
	if old.Id != 0 {
		value.Kind = old.Kind
	}
	if value.Kind == inboundTemplate {
		if len(spec.Entries) != 1 {
			return errors.New("one_inbound_per_template")
		}
		if old.Id != 0 {
			previous, err := templateSpec(tx, old)
			if err != nil {
				return err
			}
			if len(previous.Entries) != 1 || previous.Entries[0].Key != spec.Entries[0].Key {
				return errors.New("node_inbound_template_key_immutable")
			}
		}
		value.Name, value.Protocol = spec.Entries[0].Name, spec.Entries[0].Protocol
	}
	return nil
}

func updateTemplateScope(tx *gorm.DB, value *model.NodeTemplate, old model.NodeTemplate) error {
	if old.Id != 0 {
		value.Scope, value.OwnerNodeId, value.ParentTemplateId = old.Scope, old.OwnerNodeId, old.ParentTemplateId
	}
	if value.Scope == "" {
		value.Scope = "shared"
	}
	if value.Scope != "shared" && value.Scope != "private" {
		return errors.New("invalid_template_scope")
	}
	if value.Scope == "private" {
		var owner model.Node
		if value.OwnerNodeId == 0 {
			return errors.New("private_template_owner_required")
		}
		if err := tx.First(&owner, value.OwnerNodeId).Error; err != nil {
			return err
		}
	} else {
		value.OwnerNodeId = 0
	}
	return nil
}
