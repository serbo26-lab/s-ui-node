package database

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/alireza0/s-ui/database/model"
)

func restoreGuardFixture(t *testing.T) model.Node {
	t.Helper()
	_, _ = nodeBackupFixture(t)
	node := model.Node{Id: 1, Name: "Fixture node", AgentProtocol: 2, ControlEpoch: "fixture-epoch", ControlCA: "fixture-ca", ControlCertificate: "fixture-controller", SettingsVersion: 1}
	requireNodeTestSuccess(t, db.Create(&node).Error)
	requireNodeTestSuccess(t, db.Create(&model.NodeAccessState{NodeId: node.Id, DesiredRevision: 2, AppliedRevision: 2, DesiredSnapshot: json.RawMessage(`{"revision":2,"clients":[]}`)}).Error)
	requireNodeTestSuccess(t, db.Create(&model.NodeCertificateBinding{NodeId: node.Id, DesiredRevision: 1, AppliedRevision: 1, DesiredFingerprint: "fixture-request"}).Error)
	return node
}

func TestRestoreRejectsOlderNodeAccessBeforeReplacingDatabase(t *testing.T) {
	node := restoreGuardFixture(t)
	old, err := GetFullBackup("stats,changes")
	requireNodeTestSuccess(t, err)
	requireNodeTestSuccess(t, db.Model(&model.NodeAccessState{}).Where("node_id = ?", node.Id).Updates(map[string]any{"desired_revision": 3, "desired_snapshot": json.RawMessage(`{"revision":3,"clients":[]}`)}).Error)
	err = restoreDB(backupMemoryFile{bytes.NewReader(old)})
	if !errors.Is(err, errNodeBackupStateStale) {
		t.Fatalf("older node checkpoint was accepted: %v", err)
	}
	var current model.NodeAccessState
	requireNodeTestSuccess(t, db.First(&current, "node_id = ?", node.Id).Error)
	if current.DesiredRevision != 3 {
		t.Fatal("rejected restore replaced the live access intent")
	}
}

func TestNewBackupIncludesPendingNodeChangesAndLatestAccess(t *testing.T) {
	node := restoreGuardFixture(t)
	requireNodeTestSuccess(t, db.Model(&node).Updates(map[string]any{"settings_version": 2, "template_target_version": 4, "desired_revision": 2, "applied_revision": 1, "desired_snapshot": json.RawMessage(`{"revision":2,"inbounds":[]}`)}).Error)
	requireNodeTestSuccess(t, db.Model(&model.NodeAccessState{}).Where("node_id = ?", node.Id).Updates(map[string]any{"desired_revision": 3, "desired_snapshot": json.RawMessage(`{"revision":3,"clients":[]}`)}).Error)
	requireNodeTestSuccess(t, db.Create(&model.NodeTemplate{Id: 1, Name: "Updated fixture", Version: 4}).Error)
	requireNodeTestSuccess(t, db.Create(&model.NodeDomainBinding{NodeId: node.Id, Mode: "manual", FQDN: "updated.example.com", Generation: 2}).Error)
	requireNodeTestSuccess(t, db.Create(&model.NodeClientTraffic{NodeId: node.Id, ClientId: 1, Ledger: "fixture-ledger", Up: 123, Down: 456}).Error)
	requireNodeTestSuccess(t, db.Model(&model.NodeCertificateBinding{}).Where("node_id = ?", node.Id).Update("desired_revision", 2).Error)
	archive, err := GetFullBackup("stats,changes")
	requireNodeTestSuccess(t, err)
	body, _, err := readFullBackup(bytes.NewReader(archive), int64(len(archive)))
	requireNodeTestSuccess(t, err)
	candidate := openBackup(t, body)
	var saved model.Node
	var access model.NodeAccessState
	var template model.NodeTemplate
	var domain model.NodeDomainBinding
	var traffic model.NodeClientTraffic
	var certificate model.NodeCertificateBinding
	requireNodeTestSuccess(t, candidate.First(&saved, node.Id).Error)
	requireNodeTestSuccess(t, candidate.First(&access, "node_id = ?", node.Id).Error)
	requireNodeTestSuccess(t, candidate.First(&template, 1).Error)
	requireNodeTestSuccess(t, candidate.First(&domain, "node_id = ?", node.Id).Error)
	requireNodeTestSuccess(t, candidate.First(&traffic, "node_id = ?", node.Id).Error)
	requireNodeTestSuccess(t, candidate.First(&certificate, "node_id = ?", node.Id).Error)
	if saved.SettingsVersion != 2 || saved.TemplateTargetVersion != 4 || template.Version != 4 || access.DesiredRevision != 3 || access.AppliedRevision != 2 || saved.DesiredRevision != 2 || saved.AppliedRevision != 1 {
		t.Fatal("new backup omitted pending settings or access changes")
	}
	if domain.FQDN != "updated.example.com" || domain.Generation != 2 || traffic.Up != 123 || traffic.Down != 456 {
		t.Fatal("new backup omitted current resources or accounting cursors")
	}
	if certificate.DesiredRevision != 2 || certificate.AppliedRevision != 1 {
		t.Fatal("new backup omitted the pending certificate revision")
	}
	// A later ACK does not invalidate a backup of the same desired intent.
	requireNodeTestSuccess(t, db.Model(&model.NodeAccessState{}).Where("node_id = ?", node.Id).Update("applied_revision", 3).Error)
	requireNodeTestSuccess(t, db.Model(&node).Update("applied_revision", 2).Error)
	requireNodeTestSuccess(t, db.Model(&model.NodeCertificateBinding{}).Where("node_id = ?", node.Id).Update("applied_revision", 2).Error)
	requireNodeTestSuccess(t, restoreDB(backupMemoryFile{bytes.NewReader(archive)}))
}

func TestRestoreRejectsConflictingOrDifferentRegistration(t *testing.T) {
	for _, scenario := range []string{"conflicting payload", "changed epoch", "missing node", "newer structure", "pending settings", "conflicting structure", "newer certificate", "conflicting certificate"} {
		t.Run(scenario, func(t *testing.T) {
			checkConflictingNodeRestore(t, scenario)
		})
	}
}

func checkConflictingNodeRestore(t *testing.T, scenario string) {
	t.Helper()
	node := restoreGuardFixture(t)
	old, err := GetFullBackup("")
	requireNodeTestSuccess(t, err)
	switch scenario {
	case "conflicting payload":
		requireNodeTestSuccess(t, db.Model(&model.NodeAccessState{}).Where("node_id = ?", node.Id).Update("desired_snapshot", json.RawMessage(`{"revision":2,"clients":[{"name":"fixture"}]}`)).Error)
	case "changed epoch":
		requireNodeTestSuccess(t, db.Model(&node).Update("control_epoch", "new-fixture-epoch").Error)
	case "missing node":
		requireNodeTestSuccess(t, db.Model(&node).Update("id", 2).Error)
	case "newer structure":
		requireNodeTestSuccess(t, db.Model(&node).Update("desired_revision", 1).Error)
	case "pending settings":
		requireNodeTestSuccess(t, db.Model(&node).Update("settings_version", 2).Error)
	case "conflicting structure":
		requireNodeTestSuccess(t, db.Model(&node).Update("desired_snapshot", json.RawMessage(`{"inbounds":[]}`)).Error)
	case "newer certificate":
		requireNodeTestSuccess(t, db.Model(&model.NodeCertificateBinding{}).Where("node_id = ?", node.Id).Update("desired_revision", 2).Error)
	case "conflicting certificate":
		requireNodeTestSuccess(t, db.Model(&model.NodeCertificateBinding{}).Where("node_id = ?", node.Id).Update("desired_fingerprint", "different-fixture-request").Error)
	}
	if err := restoreDB(backupMemoryFile{bytes.NewReader(old)}); !errors.Is(err, errNodeBackupStateStale) {
		t.Fatalf("unsafe registration restore was accepted: %v", err)
	}
}

func TestBackupSnapshotComparisonPreservesLargeNumbers(t *testing.T) {
	if sameBackupJSON(json.RawMessage(`{"value":9007199254740992}`), json.RawMessage(`{"value":9007199254740993}`)) {
		t.Fatal("different integer values compared equal")
	}
	if !sameBackupJSON(json.RawMessage(`{"a":1,"b":2}`), json.RawMessage(`{"b":2,"a":1}`)) {
		t.Fatal("object field order changed checkpoint equality")
	}
}
