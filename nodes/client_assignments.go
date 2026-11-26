package nodes

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sort"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"gorm.io/gorm"
)

func nodeIDList(raw json.RawMessage) ([]uint, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("nodes must be an array, not null")
	}
	var ids []uint
	if len(raw) == 0 || json.Unmarshal(raw, &ids) != nil {
		return nil, errors.New("nodes must contain numeric IDs")
	}
	seen := map[uint]bool{}
	for _, id := range ids {
		if id == 0 || seen[id] {
			return nil, errors.New("nodes contains zero or duplicate IDs")
		}
		seen[id] = true
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

// Normalize a read-only echo before the legacy writer runs. A legacy list can
// never be interpreted as an instruction to grant the containing nodes.
func wholeNodeSelection(tx *gorm.DB, client *model.Client) ([]uint, error) {
	projection, previous, legacy, err := database.NodeProjection(tx, client.Id)
	if err != nil {
		return nil, err
	}
	if err := validateMigrationEcho(tx, client, projection); err != nil {
		return nil, err
	}
	selected := previous
	if client.Nodes != nil {
		selected, err = nodeIDList(client.Nodes)
		if err != nil {
			return nil, err
		}
		if err := validateWholeNodeSelection(tx, selected, legacy); err != nil {
			return nil, err
		}
	}
	var canonicalRows int64
	if client.Id != 0 && tx.Migrator().HasTable(&model.ClientNode{}) {
		if err := tx.Model(&model.ClientNode{}).Joins("JOIN nodes ON nodes.id = client_nodes.node_id").Where("client_id = ? AND nodes.assignment_mode = ?", client.Id, model.NodeAssignmentWhole).Count(&canonicalRows).Error; err != nil {
			return nil, err
		}
	}
	if client.NodeInbounds != nil && (client.Nodes != nil || canonicalRows > 0) {
		echo, err := nodeIDList(client.NodeInbounds)
		if err != nil {
			return nil, errors.New("nodeinbounds_read_only_use_nodes")
		}
		if !reflect.DeepEqual(echo, projection) || !reflect.DeepEqual(selected, previous) {
			return nil, errors.New("nodeinbounds_read_only_use_nodes")
		}
		client.NodeInbounds = nil
	}
	return selected, nil
}

func saveWholeNodeAssignments(tx *gorm.DB, client *model.Client) error {
	if client.Nodes == nil {
		return nil
	}
	ids, err := nodeIDList(client.Nodes)
	if err != nil {
		return err
	}
	var rows []model.ClientNode
	if err := tx.Where("client_id = ?", client.Id).Find(&rows).Error; err != nil {
		return err
	}
	wanted := map[uint]bool{}
	existing := map[uint]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	for _, row := range rows {
		existing[row.NodeId] = true
		if row.Active == wanted[row.NodeId] {
			continue
		}
		row.Active = wanted[row.NodeId]
		row.Generation++
		if err := tx.Save(&row).Error; err != nil {
			return err
		}
	}
	for _, id := range ids {
		if !existing[id] {
			if err := tx.Create(&model.ClientNode{ClientId: client.Id, NodeId: id, Active: true, Generation: 1}).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

// DeleteClientAssignments queues access removal before deleting legacy links.
// The caller deletes the client in the same transaction.
func DeleteClientAssignments(tx *gorm.DB, ids []uint) error {
	if err := tx.Where("client_id IN ?", ids).Delete(&model.NodeClientTraffic{}).Error; err != nil {
		return err
	}
	if err := database.RevokeClientNodes(tx, ids); err != nil {
		return err
	}
	if !tx.Migrator().HasTable(&model.ClientNodeInbound{}) {
		return nil
	}
	return tx.Where("client_id IN ?", ids).Delete(&model.ClientNodeInbound{}).Error
}

func validateMigrationEcho(tx *gorm.DB, client *model.Client, projection []uint) error {
	if client.Id != 0 && client.NodeInbounds != nil {
		var inProgress int64
		if err := tx.Model(&model.ClientNodeInbound{}).Joins("JOIN node_inbounds AS ni ON ni.id = client_node_inbounds.node_inbound_id").Joins("JOIN nodes ON nodes.id = ni.node_id").Where("client_id = ? AND nodes.assignment_mode = ?", client.Id, model.NodeAssignmentActivating).Count(&inProgress).Error; err != nil {
			return err
		}
		if inProgress > 0 {
			echo, err := nodeIDList(client.NodeInbounds)
			if err != nil || !reflect.DeepEqual(echo, projection) {
				return errors.New("migration_in_progress")
			}
		}
	}
	return nil
}

func validateWholeNodeSelection(tx *gorm.DB, selected []uint, legacy bool) error {
	if legacy {
		return errors.New("remote_assignment_migration_required")
	}
	if len(selected) > 0 {
		var count int64
		if err := tx.Model(&model.Node{}).Where("id IN ? AND assignment_mode = ?", selected, model.NodeAssignmentWhole).Count(&count).Error; err != nil {
			return err
		}
		if count != int64(len(selected)) {
			return errors.New("unknown_node_or_assignment_migration_required")
		}
	}
	return nil
}
