package nodes

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"gorm.io/gorm"
)

type MigrationClient struct {
	ClientId uint   `json:"client_id"`
	Selected []uint `json:"selected_inbounds"`
	Complete bool   `json:"complete"`
}

type MigrationReport struct {
	NodeId   uint              `json:"node_id"`
	Mode     string            `json:"mode"`
	Digest   string            `json:"digest"`
	Inbounds []uint            `json:"inbounds"`
	Clients  []MigrationClient `json:"clients"`
}

type MigrationDecision struct {
	ClientId uint   `json:"client_id"`
	Action   string `json:"action"`
}

type PrepareMigrationRequest struct {
	NodeId       uint                `json:"node_id"`
	ReportDigest string              `json:"report_digest"`
	Decisions    []MigrationDecision `json:"decisions"`
}

func migrationReport(tx *gorm.DB, nodeID uint) (MigrationReport, error) {
	report := MigrationReport{NodeId: nodeID, Inbounds: []uint{}, Clients: []MigrationClient{}}
	var node model.Node
	if err := tx.First(&node, nodeID).Error; err != nil {
		return report, err
	}
	report.Mode = node.AssignmentMode
	var inbounds []model.NodeInbound
	if err := tx.Where("node_id = ?", nodeID).Order("id").Find(&inbounds).Error; err != nil {
		return report, err
	}
	for _, in := range inbounds {
		report.Inbounds = append(report.Inbounds, in.Id)
	}
	var dangling int64
	if err := tx.Model(&model.ClientNodeInbound{}).Joins("LEFT JOIN node_inbounds AS ni ON ni.id = client_node_inbounds.node_inbound_id").Joins("LEFT JOIN clients AS c ON c.id = client_node_inbounds.client_id").Where("ni.id IS NULL OR c.id IS NULL").Count(&dangling).Error; err != nil {
		return report, err
	}
	if dangling > 0 {
		return report, errors.New("orphan_legacy_assignments_require_review")
	}
	var bindings []model.ClientNodeInbound
	if len(report.Inbounds) > 0 {
		if err := tx.Where("node_inbound_id IN ?", report.Inbounds).Order("client_id, node_inbound_id").Find(&bindings).Error; err != nil {
			return report, err
		}
	}
	byClient := map[uint][]uint{}
	for _, row := range bindings {
		byClient[row.ClientId] = append(byClient[row.ClientId], row.NodeInboundId)
	}
	clientIDs := []uint{}
	for id := range byClient {
		clientIDs = append(clientIDs, id)
	}
	sort.Slice(clientIDs, func(i, j int) bool { return clientIDs[i] < clientIDs[j] })
	type clientState struct {
		Id           uint
		Enable       bool
		Expiry       int64
		Generation   uint64
		ConfigDigest string
		Selected     []uint
	}
	states := []clientState{}
	for _, id := range clientIDs {
		var client model.Client
		if err := tx.First(&client, id).Error; err != nil {
			return report, err
		}
		selected := byClient[id]
		report.Clients = append(report.Clients, MigrationClient{ClientId: id, Selected: selected, Complete: len(selected) == len(report.Inbounds)})
		states = append(states, clientState{Id: id, Enable: client.Enable, Expiry: client.Expiry, Generation: client.NodeGeneration, ConfigDigest: versionDigest(client.Config), Selected: selected})
	}
	// Do not hash timestamps/status polling or the staging mode itself. Staging
	// changes only mode/grant rows and must not invalidate its own source digest.
	fingerprint, err := json.Marshal(struct {
		NodeId               uint
		Address, LinkAddress string
		TemplateId           uint
		Config               json.RawMessage
		ControlDigest        string
		Applied              json.RawMessage
		Inbounds             []model.NodeInbound
		Clients              []clientState
	}{node.Id, node.Address, node.LinkAddress, node.TemplateId, node.Config, versionDigest([]byte(node.ControlCA + node.ControlCertificate + node.ControlKey)), node.AppliedSnapshot, inbounds, states})
	if err != nil {
		return report, errors.New("invalid_migration_source_json")
	}
	report.Digest = versionDigest(fingerprint)
	return report, nil
}

func ReportNodeMigration(nodeID uint) (MigrationReport, error) {
	var report MigrationReport
	err := database.GetDB().Transaction(func(tx *gorm.DB) error { var err error; report, err = migrationReport(tx, nodeID); return err })
	return report, err
}

// Prepare is deliberately not Activate. Legacy bindings and live snapshots are
// retained; R2 must verify agent capabilities and source freshness before cutover.
func PrepareNodeMigration(request PrepareMigrationRequest, actor string) (model.NodeAssignmentMigration, error) {
	var migration model.NodeAssignmentMigration
	err := database.GetDB().Transaction(func(tx *gorm.DB) error {
		report, err := migrationReport(tx, request.NodeId)
		if err != nil {
			return err
		}
		if report.Mode != model.NodeAssignmentLegacy && report.Mode != model.NodeAssignmentPrepared {
			return errors.New("node_is_not_in_legacy_mode")
		}
		if request.ReportDigest == "" || report.Digest != request.ReportDigest {
			return errors.New("migration_report_conflict")
		}
		decisions := map[uint]string{}
		for _, decision := range request.Decisions {
			if decision.ClientId == 0 || decisions[decision.ClientId] != "" || (decision.Action != "assign_node" && decision.Action != "remove") {
				return errors.New("invalid_migration_decision")
			}
			decisions[decision.ClientId] = decision.Action
		}
		canonical := []MigrationDecision{}
		for _, client := range report.Clients {
			action := decisions[client.ClientId]
			if action == "" {
				if !client.Complete {
					return errors.New("partial_assignment_decision_required")
				}
				action = "assign_node"
			}
			canonical = append(canonical, MigrationDecision{ClientId: client.ClientId, Action: action})
			delete(decisions, client.ClientId)
		}
		if len(decisions) > 0 {
			return errors.New("unknown_migration_client")
		}
		body, _ := json.Marshal(canonical)
		if report.Mode == model.NodeAssignmentPrepared {
			if err := tx.First(&migration, "node_id = ?", request.NodeId).Error; err != nil {
				return err
			}
			if migration.ReportDigest == report.Digest && string(migration.Decisions) == string(body) {
				return nil
			}
		} else {
			var count int64
			if err := tx.Model(&model.ClientNode{}).Where("node_id = ?", request.NodeId).Count(&count).Error; err != nil {
				return err
			}
			if count > 0 {
				return errors.New("unexpected_prepared_grants_require_review")
			}
		}
		if err := tx.Where("node_id = ?", request.NodeId).Delete(&model.ClientNode{}).Error; err != nil {
			return err
		}
		for _, decision := range canonical {
			if decision.Action == "assign_node" {
				if err := tx.Create(&model.ClientNode{ClientId: decision.ClientId, NodeId: request.NodeId, Active: true, Generation: 1}).Error; err != nil {
					return err
				}
			}
		}
		migration = model.NodeAssignmentMigration{NodeId: request.NodeId, ReportDigest: report.Digest, State: "prepared", Decisions: body, Created: time.Now().Unix()}
		if err := tx.Save(&migration).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.Node{}).Where("id = ?", request.NodeId).Update("assignment_mode", model.NodeAssignmentPrepared).Error; err != nil {
			return err
		}
		obj, _ := json.Marshal(map[string]interface{}{"id": request.NodeId, "report_digest": report.Digest})
		return tx.Create(&model.Changes{DateTime: time.Now().Unix(), Actor: actor, Key: "nodes", Action: "preparemigration", Obj: obj}).Error
	})
	return migration, err
}
