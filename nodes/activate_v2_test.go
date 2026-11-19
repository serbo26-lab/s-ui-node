package nodes

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/nodeagent"
)

func TestV2ControlledWholeNodeCutoverPreservesCredentials(t *testing.T) {
	db, node, client := fixture(t)
	runtime := &panelSafeRuntime{}
	manager := nodeagent.NewManagerV2(uint64(node.Id), nodeagent.FileStoreV2{Directory: t.TempDir()}, runtime)
	if err := manager.Restore(nil); err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	server, identity := controlHandlerServer(t, nodeagent.HandlerV2(manager))
	node.Address = server.URL
	node.ControlCA = identity.CA
	node.ControlCertificate = identity.Certificate
	node.ControlKey = identity.Key
	db.Save(&node)
	extra := model.NodeInbound{NodeId: node.Id, Tag: "second", Type: "vless", Enable: true, Options: json.RawMessage(`{"listen":"::","listen_port":14444}`)}
	db.Create(&extra)
	if err := Reconcile(context.Background(), node.Id); err != nil {
		t.Fatal(err)
	}
	report, err := ReportNodeMigration(node.Id)
	if err != nil {
		t.Fatal(err)
	}
	request := PrepareMigrationRequest{NodeId: node.Id, ReportDigest: report.Digest, Decisions: []MigrationDecision{{ClientId: client.Id, Action: "assign_node"}}}
	if _, err := PrepareNodeMigration(request, "test"); err != nil {
		t.Fatal(err)
	}
	if links, err := ClientInbounds(db, client); err != nil || len(links) != 1 {
		t.Fatal("prepare widened subscription", err)
	}
	migration, err := ActivateNodeMigration(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if migration.State != "complete" {
		t.Fatal("confirmed cutover not completed", migration.State)
	}
	db.First(&node, node.Id)
	db.First(&client, client.Id)
	if node.AssignmentMode != model.NodeAssignmentWhole {
		t.Fatal("canonical mode not activated")
	}
	var config map[string]map[string]interface{}
	json.Unmarshal(client.Config, &config)
	if config["vless"]["uuid"] != "11111111-1111-4111-8111-111111111111" || config["tuic"]["uuid"] == nil {
		t.Fatal("cutover changed existing or omitted future credentials")
	}
	if links, err := ClientInbounds(db, client); err != nil || len(links) != 2 {
		t.Fatal("whole-node publication did not follow confirmed ACL", err)
	}
	if _, err := ActivateNodeMigration(context.Background(), request); err != nil {
		t.Fatal("idempotent activation failed", err)
	}
}

func TestV1CannotActivatePreparedWholeNodeGrants(t *testing.T) {
	_, node, _ := fixture(t)
	report, err := ReportNodeMigration(node.Id)
	if err != nil {
		t.Fatal(err)
	}
	request := PrepareMigrationRequest{NodeId: node.Id, ReportDigest: report.Digest}
	if _, err := PrepareNodeMigration(request, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateNodeMigration(context.Background(), request); err == nil {
		t.Fatal("v1 agent activated independent access semantics")
	}
}
