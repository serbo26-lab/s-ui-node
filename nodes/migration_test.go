package nodes

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/alireza0/s-ui/database/model"
)

func TestMigrationReportAndPrepareNeverBroadenLegacyGrants(t *testing.T) {
	db, node, client := fixture(t)
	extra := model.NodeInbound{Id: 2, NodeId: node.Id, Tag: "second", Type: "vless", Enable: true, Options: json.RawMessage(`{"listen":"::","listen_port":14444}`)}
	if err := db.Create(&extra).Error; err != nil {
		t.Fatal(err)
	}
	before, err := Compile(db, node)
	if err != nil {
		t.Fatal(err)
	}
	report, err := ReportNodeMigration(node.Id)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Clients) != 1 || report.Clients[0].Complete || len(report.Clients[0].Selected) != 1 {
		t.Fatal("partial legacy grant was classified as complete")
	}
	var count int64
	db.Model(&model.ClientNode{}).Count(&count)
	if count != 0 {
		t.Fatal("read-only report created grants")
	}
	if _, err := PrepareNodeMigration(PrepareMigrationRequest{NodeId: node.Id, ReportDigest: report.Digest}, "test"); err == nil || err.Error() != "partial_assignment_decision_required" {
		t.Fatal("partial access widened without explicit decision", err)
	}
	db.Model(&model.ClientNode{}).Count(&count)
	if count != 0 {
		t.Fatal("failed prepare left rows")
	}
	request := PrepareMigrationRequest{NodeId: node.Id, ReportDigest: report.Digest, Decisions: []MigrationDecision{{ClientId: client.Id, Action: "assign_node"}}}
	prepared, err := PrepareNodeMigration(request, "test")
	if err != nil {
		t.Fatal(err)
	}
	if prepared.State != "prepared" {
		t.Fatal("migration activated before agent transition")
	}
	db.First(&node, node.Id)
	if node.AssignmentMode != model.NodeAssignmentPrepared {
		t.Fatal("incorrect prepared mode")
	}
	after, err := Compile(db, node)
	if err != nil {
		t.Fatal(err)
	}
	if string(before.Deployment.Config) != string(after.Deployment.Config) {
		t.Fatal("prepared node used broadened grants")
	}
	if _, err := PrepareNodeMigration(request, "test"); err != nil {
		t.Fatal("idempotent preparation failed", err)
	}
	if err := db.Model(&model.Client{}).Where("id = ?", client.Id).Update("expiry", 123).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareNodeMigration(request, "test"); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatal("stale report accepted", err)
	}
	public, _ := json.Marshal(report)
	if strings.Contains(string(public), "private_key") || strings.Contains(string(public), "uuid") {
		t.Fatal("report leaked private configuration")
	}
}

func TestWholeNodeCompilerDynamicallyIncludesNewInbound(t *testing.T) {
	db, node, client := fixture(t)
	node.AssignmentMode = model.NodeAssignmentWhole
	db.Save(&node)
	if err := db.Create(&model.ClientNode{ClientId: client.Id, NodeId: node.Id, Active: true, Generation: 1}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Where("client_id = ?", client.Id).Delete(&model.ClientNodeInbound{}).Error; err != nil {
		t.Fatal(err)
	}
	first := confirm(t, db, node)
	if len(first.Inbounds) != 1 {
		t.Fatal("initial whole-node connection missing")
	}
	extra := model.NodeInbound{NodeId: node.Id, Tag: "new", Type: "vless", Enable: true, Options: json.RawMessage(`{"listen":"::","listen_port":14444}`)}
	if err := db.Create(&extra).Error; err != nil {
		t.Fatal(err)
	}
	endpoints, err := ClientInbounds(db, client)
	if err != nil || len(endpoints) != 1 {
		t.Fatal("unapplied new connection published", err)
	}
	second := confirm(t, db, node)
	if len(second.Inbounds) != 2 {
		t.Fatal("new connection did not inherit whole-node clients")
	}
	endpoints, err = ClientInbounds(db, client)
	if err != nil || len(endpoints) != 2 {
		t.Fatal("whole-node subscription did not update", err)
	}
	var legacyCount int64
	db.Model(&model.ClientNodeInbound{}).Count(&legacyCount)
	if legacyCount != 0 {
		t.Fatal("dynamic node access was duplicated into inbound bindings")
	}
	db.Model(&model.NodeInbound{}).Where("id = ?", extra.Id).Update("enable", false)
	confirm(t, db, node)
	endpoints, err = ClientInbounds(db, client)
	if err != nil || len(endpoints) != 1 {
		t.Fatal("disabled connection remains in subscription", err)
	}
}
