package nodes

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sort"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/nodeagent"
	"github.com/gofrs/uuid/v5"
	"gorm.io/gorm"
)

// Fill only missing protocol credentials before local links/config are rebuilt.
// Existing UUIDs/passwords retain their values when a node is assigned.
func PrepareClientCredentials(tx *gorm.DB, client *model.Client) error {
	if !tx.Migrator().HasTable(&model.ClientNodeInbound{}) {
		return nil
	}
	whole, err := wholeNodeSelection(tx, client)
	if err != nil {
		return err
	}
	var ids []uint
	if client.NodeInbounds != nil {
		if bytes.Equal(bytes.TrimSpace(client.NodeInbounds), []byte("null")) {
			return errors.New("nodeinbounds must be an array, not null")
		}
		if err := json.Unmarshal(client.NodeInbounds, &ids); err != nil {
			return errors.New("nodeinbounds must contain numeric IDs")
		}
	} else if client.Id != 0 {
		ids, err = database.LegacyNodeInboundIDs(tx, client.Id)
		if err != nil {
			return err
		}
	}
	if len(ids) == 0 && len(whole) == 0 {
		return preserveNodeGeneration(tx, client, ids)
	}
	var inbounds []model.NodeInbound
	if err := tx.Where("id in ?", ids).Find(&inbounds).Error; err != nil {
		return err
	}
	if len(whole) > 0 {
		for _, kind := range nodeagent.InboundTypes(true) {
			if nodeagent.ProxyInbound(kind) {
				continue
			}
			inbounds = append(inbounds, model.NodeInbound{Type: kind})
		}
	}
	var config map[string]map[string]interface{}
	if err := json.Unmarshal(client.Config, &config); err != nil {
		return err
	}
	if config == nil {
		config = map[string]map[string]interface{}{}
	}
	if len(whole) > 0 && client.Id != 0 {
		var old model.Client
		if err := tx.First(&old, client.Id).Error; err != nil {
			return err
		}
		var previous map[string]map[string]interface{}
		if err := json.Unmarshal(old.Config, &previous); err != nil {
			return err
		}
		for kind, user := range previous {
			if !nodeagent.SupportsInbound(kind, true) && kind != "shadowsocks16" {
				continue
			}
			if config[kind] == nil {
				config[kind] = map[string]interface{}{}
				for field, value := range user {
					config[kind][field] = value
				}
				config[kind]["name"] = client.Name
			}
			for _, field := range []string{"uuid", "password", "auth_str", "userkey", "username"} {
				if _, exists := config[kind][field]; !exists {
					if value, ok := user[field]; ok {
						config[kind][field] = value
					}
				}
			}
		}
	}
	for _, inbound := range inbounds {
		user := config[inbound.Type]
		newUser := user == nil
		if user == nil {
			user = map[string]interface{}{"name": client.Name}
			config[inbound.Type] = user
		}
		if nodeagent.NeedsUUID(inbound.Type) {
			if value, exists := user["uuid"]; exists && value != nil {
				if _, ok := value.(string); !ok {
					return errors.New("node UUID must be a string")
				}
			}
			value, _ := user["uuid"].(string)
			if value == "" {
				generated, err := uuid.NewV4()
				if err != nil {
					return err
				}
				value = generated.String()
				user["uuid"] = value
			}
			if _, err := uuid.FromString(value); err != nil {
				return errors.New("invalid UUID for selected node protocol")
			}
		}
		if nodeagent.NeedsPassword(inbound.Type) {
			if value, exists := user["password"]; exists && value != nil {
				if _, ok := value.(string); !ok {
					return errors.New("node password must be a string")
				}
			}
			value, _ := user["password"].(string)
			if value == "" {
				buf := make([]byte, 24)
				if _, err := rand.Read(buf); err != nil {
					return err
				}
				user["password"] = base64.RawURLEncoding.EncodeToString(buf)
			}
		}
		if inbound.Type == "vless" && newUser {
			if _, ok := user["flow"]; !ok {
				user["flow"] = "xtls-rprx-vision"
			}
		}
	}
	value, err := json.Marshal(config)
	if err == nil {
		client.Config = value
		return preserveNodeGeneration(tx, client, ids)
	}
	return err
}

func preserveNodeGeneration(tx *gorm.DB, client *model.Client, selected []uint) error {
	whole, err := wholeNodeSelection(tx, client)
	if err != nil {
		return err
	}
	if client.Id == 0 {
		client.NodeAccessChanged = len(selected) > 0 || len(whole) > 0
		return nil
	}
	var old model.Client
	if err := tx.First(&old, client.Id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	client.NodeGeneration = old.NodeGeneration
	var previous []uint
	previous, err = database.LegacyNodeInboundIDs(tx, client.Id)
	if err != nil {
		return err
	}
	_, previousWhole, _, err := database.NodeProjection(tx, client.Id)
	if err != nil {
		return err
	}
	if len(previous) == 0 && len(selected) == 0 && len(whole) == 0 && len(previousWhole) == 0 {
		return nil
	}
	selected = append([]uint{}, selected...)
	sort.Slice(selected, func(i, j int) bool { return selected[i] < selected[j] })
	var before, after interface{}
	if err := json.Unmarshal(old.Config, &before); err != nil {
		return err
	}
	if err := json.Unmarshal(client.Config, &after); err != nil {
		return err
	}
	if old.Enable != client.Enable || old.Expiry != client.Expiry || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(previous, selected) || !reflect.DeepEqual(previousWhole, whole) {
		client.NodeGeneration++
		client.NodeAccessChanged = true
	}
	return nil
}

func HydrateClientAssignments(db *gorm.DB, clients []model.Client) error {
	ids := make([]uint, 0, len(clients))
	for _, client := range clients {
		ids = append(ids, client.Id)
	}
	projections, err := database.NodeProjections(db, ids)
	if err != nil {
		return err
	}
	for i := range clients {
		p := projections[clients[i].Id]
		clients[i].NodeInbounds, _ = json.Marshal(p.Inbounds)
		clients[i].NodeMigrationRequired = p.Legacy
		if p.Legacy {
			clients[i].Nodes = nil
		} else {
			clients[i].Nodes, _ = json.Marshal(p.Nodes)
		}
	}
	return nil
}

func SaveClientAssignments(tx *gorm.DB, client *model.Client) error {
	if err := saveWholeNodeAssignments(tx, client); err != nil {
		return err
	}
	if client.NodeAccessChanged {
		if err := database.QueueClientNodeAccess(tx, []uint{client.Id}); err != nil {
			return err
		}
	}
	if client.NodeInbounds == nil {
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(client.NodeInbounds), []byte("null")) {
		return errors.New("nodeinbounds must be an array, not null")
	}
	var ids []uint
	if err := json.Unmarshal(client.NodeInbounds, &ids); err != nil {
		return errors.New("nodeinbounds must contain numeric node inbound IDs")
	}
	seen := map[uint]bool{}
	for _, id := range ids {
		if id == 0 || seen[id] {
			return errors.New("nodeinbounds contains zero or duplicate IDs")
		}
		seen[id] = true
	}
	if len(ids) > 0 {
		var converted int64
		if err := tx.Model(&model.NodeInbound{}).Joins("JOIN nodes ON nodes.id = node_inbounds.node_id").Where("node_inbounds.id IN ? AND nodes.assignment_mode = ?", ids, model.NodeAssignmentWhole).Count(&converted).Error; err != nil {
			return err
		}
		if converted > 0 {
			return errors.New("nodeinbounds_read_only_use_nodes")
		}
		var count int64
		if err := tx.Model(&model.NodeInbound{}).Where("id in ?", ids).Count(&count).Error; err != nil {
			return err
		}
		if count != int64(len(ids)) {
			return errors.New("unknown node inbound ID; local inbound IDs cannot be used in nodeinbounds")
		}
	}
	if err := tx.Where("client_id = ?", client.Id).Delete(&model.ClientNodeInbound{}).Error; err != nil {
		return err
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		if err := tx.Create(&model.ClientNodeInbound{ClientId: client.Id, NodeInboundId: id}).Error; err != nil {
			return err
		}
	}
	if client.NodeAccessChanged {
		return database.QueueClientNodeAccess(tx, []uint{client.Id})
	}
	return nil
}

// PrepareClientEnableChange queues reconciliation and adds the access fence to
// the caller's bulk enable update.
func PrepareClientEnableChange(tx *gorm.DB, ids []uint, enable bool, columns map[string]interface{}) error {
	if err := database.QueueClientNodeAccess(tx, ids); err != nil {
		return err
	}
	columns["node_generation"] = gorm.Expr("CASE WHEN enable = ? THEN node_generation + 1 ELSE node_generation END", !enable)
	return nil
}

func PrepareClientResets(tx *gorm.DB, clients []*model.Client) error {
	for _, client := range clients {
		var old model.Client
		if err := tx.Select("id", "enable", "expiry", "node_generation").First(&old, client.Id).Error; err != nil {
			return err
		}
		client.NodeGeneration = old.NodeGeneration
		if old.Enable != client.Enable || old.Expiry != client.Expiry {
			client.NodeGeneration++
			if err := database.QueueClientNodeAccess(tx, []uint{client.Id}); err != nil {
				return err
			}
		}
	}
	return nil
}
