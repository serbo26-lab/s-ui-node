package nodes

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/nodeagent"
	"github.com/gofrs/uuid/v5"
	"gorm.io/gorm"
)

type Blueprint struct {
	Key       string          `json:"key"`
	Tag       string          `json:"tag"`
	Type      string          `json:"type"`
	Enable    bool            `json:"enable"`
	Options   json.RawMessage `json:"options"`
	ClientTLS json.RawMessage `json:"client_tls"`
}

func validateInbound(value *model.NodeInbound, extended bool) error {
	if strings.TrimSpace(value.Tag) == "" {
		return errors.New("remote inbound needs a tag")
	}
	if !nodeagent.SupportsInbound(value.Type, extended) {
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
	for _, key := range []string{"users", "type", "tag", "id", "tls_id", "out_json", "addrs"} {
		delete(options, key)
	}
	value.Options, _ = json.Marshal(options)
	_, _, err := clientTLS(*value)
	return err
}

func normalizeBlueprints(value *model.NodeTemplate, old model.NodeTemplate) error {
	if len(value.Blueprints) == 0 || string(value.Blueprints) == "null" {
		value.Blueprints = json.RawMessage(`[]`)
	}
	var list, previous []Blueprint
	if err := json.Unmarshal(value.Blueprints, &list); err != nil {
		return errors.New("template blueprints must be an array")
	}
	_ = json.Unmarshal(old.Blueprints, &previous)
	oldTypes := map[string]string{}
	for _, slot := range previous {
		oldTypes[slot.Key] = slot.Type
	}
	keys, tags := map[string]bool{}, map[string]bool{}
	for i := range list {
		item := &list[i]
		if item.Key == "" {
			key, err := uuid.NewV4()
			if err != nil {
				return err
			}
			item.Key = key.String()
		}
		if len(item.Key) > 128 || keys[item.Key] || tags[item.Tag] {
			return errors.New("duplicate template inbound key/tag")
		}
		if prior, ok := oldTypes[item.Key]; ok && prior != item.Type {
			return errors.New("create a new template inbound to change its protocol")
		}
		keys[item.Key], tags[item.Tag] = true, true
		inbound := model.NodeInbound{Tag: item.Tag, Type: item.Type, Enable: item.Enable, Options: item.Options, ClientTLS: item.ClientTLS}
		if err := validateInbound(&inbound, false); err != nil {
			return err
		}
		item.Options = inbound.Options
	}
	value.Blueprints, _ = json.Marshal(list)
	config, err := decodeObject(value.Config)
	if err != nil {
		return err
	}
	inbounds := []interface{}{}
	for _, item := range list {
		var options map[string]interface{}
		_ = json.Unmarshal(item.Options, &options)
		options["type"] = item.Type
		inbounds = append(inbounds, options)
	}
	config["inbounds"] = inbounds
	body, _ := json.Marshal(config)
	return nodeagent.ValidateCertificateReferences(body)
}

// Object fields merge recursively; arrays/scalars are atomic. Missing fields
// are distinguished from explicit null so a deliberate node-side deletion stays.
func mergeTemplate(old, current, next interface{}) interface{} {
	if reflect.DeepEqual(old, current) {
		return next
	}
	oldMap, oldOK := old.(map[string]interface{})
	currentMap, currentOK := current.(map[string]interface{})
	nextMap, nextOK := next.(map[string]interface{})
	if !currentOK || !nextOK {
		return current
	}
	if !oldOK {
		oldMap = map[string]interface{}{}
	}
	result := map[string]interface{}{}
	keys := map[string]bool{}
	for key := range oldMap {
		keys[key] = true
	}
	for key := range currentMap {
		keys[key] = true
	}
	for key := range nextMap {
		keys[key] = true
	}
	for key := range keys {
		a, aOK := oldMap[key]
		b, bOK := currentMap[key]
		c, cOK := nextMap[key]
		if aOK == bOK && reflect.DeepEqual(a, b) {
			if cOK {
				result[key] = c
			}
			continue
		}
		if !bOK {
			continue
		}
		if !cOK {
			result[key] = b
			continue
		}
		result[key] = mergeTemplate(a, b, c)
	}
	return result
}

func decodeObject(raw json.RawMessage) (map[string]interface{}, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]interface{}{}, nil
	}
	var value map[string]interface{}
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return nil, errors.New("node configuration must be an object")
	}
	return value, nil
}

func applyTemplate(tx *gorm.DB, node *model.Node, targetID uint) error {
	if targetID == 0 {
		return errors.New("select a node template")
	}
	var template model.NodeTemplate
	if err := tx.First(&template, targetID).Error; err != nil {
		return err
	}
	if template.SchemaVersion == 1 {
		return bindLiveTemplate(tx, node, template, false)
	}
	if node.TemplateTargetVersion > 0 {
		return errors.New("live_template_cannot_use_legacy_copy")
	}
	oldBase, err := decodeObject(node.TemplateBase)
	if err != nil {
		return err
	}
	current, err := decodeObject(node.Config)
	if err != nil {
		return err
	}
	// Adopt the known legacy base as an inherited baseline, not as overrides.
	if len(node.Config) == 0 && node.TemplateId != 0 {
		var legacy model.NodeTemplate
		if err := tx.First(&legacy, node.TemplateId).Error; err != nil {
			return err
		}
		current, err = decodeObject(legacy.Config)
		if err != nil {
			return err
		}
		oldBase = current
	}
	next, err := decodeObject(template.Config)
	if err != nil {
		return err
	}
	node.Config, _ = json.Marshal(mergeTemplate(oldBase, current, next))
	node.TemplateBase = template.Config
	var slots []Blueprint
	if len(template.Blueprints) > 0 && string(template.Blueprints) != "null" {
		if err := json.Unmarshal(template.Blueprints, &slots); err != nil {
			return err
		}
	}
	var existing []model.NodeInbound
	if err := tx.Where("node_id = ?", node.Id).Order("id").Find(&existing).Error; err != nil {
		return err
	}
	kept := map[uint]bool{}
	for _, slot := range slots {
		wanted := Blueprint{Tag: slot.Tag, Type: slot.Type, Enable: slot.Enable, Options: slot.Options, ClientTLS: slot.ClientTLS}
		baseJSON, _ := json.Marshal(wanted)
		value := model.NodeInbound{NodeId: node.Id, Tag: slot.Tag, Type: slot.Type, Enable: slot.Enable, Options: slot.Options, ClientTLS: slot.ClientTLS}
		for _, previous := range existing {
			if previous.SourceTemplateId != targetID || previous.TemplateKey != slot.Key {
				continue
			}
			if previous.Type != slot.Type {
				return errors.New("template protocol changed; create a new inbound")
			}
			var old interface{}
			_ = json.Unmarshal(previous.TemplateBase, &old)
			currentJSON, _ := json.Marshal(Blueprint{Tag: previous.Tag, Type: previous.Type, Enable: previous.Enable, Options: previous.Options, ClientTLS: previous.ClientTLS})
			var current, next interface{}
			_ = json.Unmarshal(currentJSON, &current)
			_ = json.Unmarshal(baseJSON, &next)
			merged, _ := json.Marshal(mergeTemplate(old, current, next))
			var result Blueprint
			if err := json.Unmarshal(merged, &result); err != nil {
				return err
			}
			value = previous
			value.Tag, value.Type, value.Enable, value.Options, value.ClientTLS = result.Tag, result.Type, result.Enable, result.Options, result.ClientTLS
			break
		}
		if err := validateInbound(&value, false); err != nil {
			return err
		}
		value.SourceTemplateId, value.TemplateKey, value.TemplateBase = targetID, slot.Key, json.RawMessage(baseJSON)
		if err := tx.Save(&value).Error; err != nil {
			return fmt.Errorf("template inbound conflicts with an existing tag: %w", err)
		}
		kept[value.Id] = true
	}
	// Removing a blueprint detaches its old instances. It never silently deletes
	// customer assignments or a node's independently edited working inbound.
	for _, previous := range existing {
		if previous.SourceTemplateId != 0 && !kept[previous.Id] {
			if err := tx.Model(&model.NodeInbound{}).Where("id = ?", previous.Id).Updates(map[string]interface{}{"source_template_id": 0, "template_key": "", "template_base": nil}).Error; err != nil {
				return err
			}
		}
	}
	node.TemplateId = targetID
	return tx.Save(node).Error
}

func resolveNodeParameters(raw json.RawMessage, node model.Node) (json.RawMessage, error) {
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	var resolve func(interface{}) interface{}
	resolve = func(value interface{}) interface{} {
		switch x := value.(type) {
		case string:
			return strings.NewReplacer("{{NODE_ADDRESS}}", node.LinkAddress, "{{NODE_NAME}}", node.Name, "{{NODE_ID}}", strconv.FormatUint(uint64(node.Id), 10)).Replace(x)
		case map[string]interface{}:
			for key, item := range x {
				x[key] = resolve(item)
			}
		case []interface{}:
			for i, item := range x {
				x[i] = resolve(item)
			}
		}
		return value
	}
	return json.Marshal(resolve(value))
}
