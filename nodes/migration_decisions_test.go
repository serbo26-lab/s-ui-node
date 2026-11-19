package nodes

import (
	"encoding/json"
	"testing"

	"github.com/alireza0/s-ui/database/model"
)

func TestCompleteLegacyGrantCanBePreparedWithoutActivation(t *testing.T) {
	db, node, _ := fixture(t)
	report, err := ReportNodeMigration(node.Id)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Clients[0].Complete {
		t.Fatal("complete exact grant not recognised")
	}
	if _, err := PrepareNodeMigration(PrepareMigrationRequest{NodeId: node.Id, ReportDigest: report.Digest}, "test"); err != nil {
		t.Fatal(err)
	}
	var grant model.ClientNode
	if err := db.First(&grant).Error; err != nil || !grant.Active {
		t.Fatal("prepared grant missing", err)
	}
	var stored model.Node
	db.First(&stored, node.Id)
	if stored.AssignmentMode != model.NodeAssignmentPrepared {
		t.Fatal("preparation activated new access")
	}
}

func TestMigrationExplicitRemovalAndInvalidDecisions(t *testing.T) {
	db, node, client := fixture(t)
	if err := db.Create(&model.NodeInbound{NodeId: node.Id, Tag: "unassigned", Type: "vless", Enable: false, Options: json.RawMessage(`{"listen_port":14444}`)}).Error; err != nil {
		t.Fatal(err)
	}
	report, err := ReportNodeMigration(node.Id)
	if err != nil {
		t.Fatal(err)
	}
	if report.Clients[0].Complete {
		t.Fatal("unselected disabled connection ignored in migration review")
	}
	for _, decisions := range [][]MigrationDecision{
		{{ClientId: client.Id, Action: "activate"}},
		{{ClientId: 999, Action: "assign_node"}},
		{{ClientId: client.Id, Action: "remove"}, {ClientId: client.Id, Action: "remove"}},
	} {
		if _, err := PrepareNodeMigration(PrepareMigrationRequest{NodeId: node.Id, ReportDigest: report.Digest, Decisions: decisions}, "test"); err == nil {
			t.Fatal("invalid migration decisions accepted")
		}
	}
	if _, err := PrepareNodeMigration(PrepareMigrationRequest{NodeId: node.Id, ReportDigest: report.Digest, Decisions: []MigrationDecision{{ClientId: client.Id, Action: "remove"}}}, "test"); err != nil {
		t.Fatal(err)
	}
	var grants, legacy int64
	db.Model(&model.ClientNode{}).Count(&grants)
	db.Model(&model.ClientNodeInbound{}).Count(&legacy)
	if grants != 0 || legacy != 1 {
		t.Fatal("prepared removal changed live legacy access or created broad grant")
	}
}
