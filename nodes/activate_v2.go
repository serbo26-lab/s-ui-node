package nodes

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/nodeagent"
	"github.com/gofrs/uuid/v5"
	"gorm.io/gorm"
)

func ensureMigrationCredentials(tx *gorm.DB, nodeID uint) error {
	var grants []model.ClientNode
	if err := tx.Where("node_id = ? AND active = ?", nodeID, true).Find(&grants).Error; err != nil {
		return err
	}
	for _, grant := range grants {
		var client model.Client
		if err := tx.First(&client, grant.ClientId).Error; err != nil {
			return err
		}
		var config map[string]map[string]interface{}
		if json.Unmarshal(client.Config, &config) != nil {
			return errors.New("invalid_migration_client_config")
		}
		if config == nil {
			config = map[string]map[string]interface{}{}
		}
		for _, kind := range []string{"vless", "tuic", "hysteria2"} {
			user := config[kind]
			if user == nil {
				user = map[string]interface{}{"name": client.Name}
				config[kind] = user
			}
			if kind == "vless" || kind == "tuic" {
				if value, exists := user["uuid"]; !exists || value == "" {
					id, err := uuid.NewV4()
					if err != nil {
						return err
					}
					user["uuid"] = id.String()
				}
			}
			if kind == "tuic" || kind == "hysteria2" {
				if value, exists := user["password"]; !exists || value == "" {
					buf := make([]byte, 24)
					if _, err := rand.Read(buf); err != nil {
						return err
					}
					user["password"] = base64.RawURLEncoding.EncodeToString(buf)
				}
			}
		}
		credentials := map[string]json.RawMessage{}
		for _, kind := range []string{"vless", "tuic", "hysteria2"} {
			credentials[kind], _ = json.Marshal(config[kind])
		}
		probe := nodeagent.AccessSnapshot{NodeID: uint64(nodeID), Epoch: "validation", Revision: 1, Clients: []nodeagent.Grant{{Name: userName(client), All: true, Credentials: credentials}}}
		if err := probe.Validate(); err != nil {
			return errors.New("invalid_existing_migration_credentials")
		}
		body, err := json.Marshal(config)
		if err != nil {
			return err
		}
		if err := tx.Model(&client).Update("config", json.RawMessage(body)).Error; err != nil {
			return err
		}
	}
	return nil
}

// Explicit activation is separate from R1 preparation. Only a pinned v2 agent
// can execute it; the durable activating mode survives a panel/network restart.
func ActivateNodeMigration(ctx context.Context, request PrepareMigrationRequest, actors ...string) (model.NodeAssignmentMigration, error) {
	var migration model.NodeAssignmentMigration
	err := database.GetDB().Transaction(func(tx *gorm.DB) error {
		var node model.Node
		if err := tx.First(&node, request.NodeId).Error; err != nil {
			return err
		}
		if err := tx.First(&migration, "node_id = ?", node.Id).Error; err != nil {
			return err
		}
		if request.ReportDigest == "" || migration.ReportDigest != request.ReportDigest {
			return errors.New("migration_report_conflict")
		}
		if migration.State == "complete" || migration.State == "activating" {
			return nil
		}
		if node.AgentProtocol != 2 || node.ControlEpoch == "" {
			return errors.New("agent_v2_upgrade_required")
		}
		if node.AssignmentMode != model.NodeAssignmentPrepared || migration.State != "prepared" {
			return errors.New("migration_is_not_prepared")
		}
		report, err := migrationReport(tx, node.Id)
		if err != nil {
			return err
		}
		if report.Digest != request.ReportDigest {
			return errors.New("migration_report_conflict")
		}
		if err := ensureMigrationCredentials(tx, node.Id); err != nil {
			return err
		}
		if err := tx.Model(&node).Update("assignment_mode", model.NodeAssignmentActivating).Error; err != nil {
			return err
		}
		migration.State = "activating"
		if err := tx.Save(&migration).Error; err != nil {
			return err
		}
		actor := "MigrationJob"
		if len(actors) > 0 {
			actor = actors[0]
		}
		obj, _ := json.Marshal(map[string]interface{}{"id": node.Id, "report_digest": request.ReportDigest})
		if err := tx.Create(&model.Changes{DateTime: time.Now().Unix(), Actor: actor, Key: "nodes", Action: "activatemigration", Obj: obj}).Error; err != nil {
			return err
		}
		return database.QueueNodeTasks(tx, []uint{node.Id}, "access")
	})
	if err != nil {
		return migration, err
	}
	if migration.State == "activating" {
		_ = ReconcileAccess(ctx, request.NodeId)
		_ = database.GetDB().First(&migration, "node_id = ?", request.NodeId).Error
	}
	return migration, nil
}

func finishMigration(tx *gorm.DB, node model.Node, status nodeagent.StatusV2) error {
	if node.AssignmentMode != model.NodeAssignmentActivating || !status.Running || !node.AgentRunning {
		return nil
	}
	var access model.NodeAccessState
	if err := tx.First(&access, "node_id = ?", node.Id).Error; err != nil {
		return err
	}
	if access.DesiredRevision == 0 || access.DesiredRevision != access.AppliedRevision {
		return nil
	}
	fresh, err := compileAccess(tx, node, extendedInboundsAvailable(tx, node, status), proxyInboundsAvailable(tx, node, status))
	if err != nil {
		return err
	}
	body, err := json.Marshal(fresh)
	if err != nil {
		return err
	}
	if versionDigest(body) != access.DesiredFingerprint {
		return nil
	}
	if err := tx.Model(&model.Node{}).Where("id = ? AND assignment_mode = ?", node.Id, model.NodeAssignmentActivating).Update("assignment_mode", model.NodeAssignmentWhole).Error; err != nil {
		return err
	}
	return tx.Model(&model.NodeAssignmentMigration{}).Where("node_id = ? AND state = ?", node.Id, "activating").Update("state", "complete").Error
}
