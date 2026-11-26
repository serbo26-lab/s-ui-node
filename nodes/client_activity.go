package nodes

import (
	"encoding/json"
	"time"

	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/nodeagent"
	"gorm.io/gorm"
)

// Activity is independent from traffic charts and never increments client quota.
func recordClientActivity(db *gorm.DB, node model.Node, sample *nodeagent.TrafficSample, observed time.Time) error {
	if sample == nil || len(sample.Activity) == 0 || len(sample.Users) > 0 {
		return nil
	}
	return db.Transaction(func(tx *gorm.DB) error {
		var current model.Node
		found := tx.Where("id = ? AND address = ? AND control_epoch = ? AND management_generation = ?", node.Id, node.Address, node.ControlEpoch, node.ManagementGeneration).Find(&current)
		if found.Error != nil || found.RowsAffected == 0 {
			return found.Error
		}
		var clients []model.Client
		query := tx.Model(&model.Client{})
		if current.AssignmentMode == model.NodeAssignmentWhole || current.AssignmentMode == model.NodeAssignmentActivating {
			query = query.Where("clients.id IN (?)", tx.Model(&model.ClientNode{}).Select("client_id").Where("node_id = ? AND active = ?", current.Id, true))
		} else {
			query = query.Where("clients.id IN (?)", tx.Model(&model.ClientNodeInbound{}).Select("client_node_inbounds.client_id").Joins("JOIN node_inbounds AS ni ON ni.id = client_node_inbounds.node_inbound_id").Where("ni.node_id = ?", current.Id))
		}
		if err := query.Find(&clients).Error; err != nil {
			return err
		}
		aliases := map[string]uint{}
		add := func(name string, id uint) {
			if name == "" {
				return
			}
			if old, ok := aliases[name]; ok && old != id {
				aliases[name] = 0
			} else {
				aliases[name] = id
			}
		}
		byID := map[uint]model.Client{}
		for _, client := range clients {
			byID[client.Id] = client
			add(effectiveUserName(tx, current, client), client.Id)
			var credentials map[string]json.RawMessage
			if json.Unmarshal(client.Config, &credentials) != nil {
				continue
			}
			for kind, raw := range credentials {
				if !nodeagent.UsernameAuth(kind) {
					continue
				}
				var auth struct {
					Username string `json:"username"`
				}
				if json.Unmarshal(raw, &auth) == nil {
					add(auth.Username, client.Id)
				}
			}
		}
		times := map[uint]int64{}
		for name, stamp := range sample.Activity {
			id := aliases[name]
			client, ok := byID[id]
			if !ok || stamp <= 0 || stamp < client.CreatedAt || stamp > observed.Add(5*time.Minute).Unix() {
				continue
			}
			times[id] = max(times[id], min(stamp, observed.Unix()))
		}
		for id, stamp := range times {
			if stamp <= byID[id].OnlineAt {
				continue
			}
			if err := tx.Model(&model.Client{}).Where("id = ? AND (online_at IS NULL OR online_at < ?)", id, stamp).Update("online_at", stamp).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
