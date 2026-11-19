package nodes

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/nodeagent"
	"gorm.io/gorm"
)

func templateFixture(t *testing.T) (*gorm.DB, model.NodeTemplate, model.Node) {
	t.Helper()
	db, node, _ := fixture(t)
	value := model.NodeTemplate{Name: "repeatable", Config: json.RawMessage(`{"log":{"level":"warn"}}`), Blueprints: json.RawMessage(`[{"key":"vless-slot","tag":"templated","type":"vless","enable":true,"options":{"listen":"::","listen_port":14444,"tls":{"enabled":false,"server_name":"{{NODE_ADDRESS}}"}},"client_tls":{}}]`)}
	if err := normalizeBlueprints(&value, model.NodeTemplate{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&value).Error; err != nil {
		t.Fatal(err)
	}
	return db, value, node
}

func TestTemplateReapplyKeepsOverridesIDsAndClientBindings(t *testing.T) {
	db, template, node := templateFixture(t)
	apply := func() {
		t.Helper()
		if err := db.Transaction(func(tx *gorm.DB) error { return applyTemplate(tx, &node, template.Id) }); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	var first model.NodeInbound
	db.Where("template_key = ?", "vless-slot").First(&first)
	if first.Id == 0 || first.Id == 1 {
		t.Fatal("template did not create an independent remote inbound")
	}
	if err := db.Create(&model.ClientNodeInbound{ClientId: 1, NodeInboundId: first.Id}).Error; err != nil {
		t.Fatal(err)
	}
	first.Options = json.RawMessage(`{"listen":"::","listen_port":24444,"tls":{"enabled":false,"server_name":"override.example","key":["node-only-key"]}}`)
	if err := db.Save(&first).Error; err != nil {
		t.Fatal(err)
	}
	template.Blueprints = json.RawMessage(`[{"key":"vless-slot","tag":"renamed","type":"vless","enable":true,"options":{"listen":"0.0.0.0","listen_port":15555,"tls":{"enabled":false,"server_name":"new-default.example"}},"client_tls":{}}]`)
	if err := db.Save(&template).Error; err != nil {
		t.Fatal(err)
	}
	apply()
	apply()
	var updated model.NodeInbound
	db.First(&updated, first.Id)
	var options map[string]interface{}
	_ = json.Unmarshal(updated.Options, &options)
	if options["listen_port"] != float64(24444) || options["listen"] != "0.0.0.0" || updated.Tag != "renamed" {
		t.Fatal("template update lost overrides or failed to inherit unchanged fields")
	}
	tls := options["tls"].(map[string]interface{})
	if tls["server_name"] != "override.example" || tls["key"] == nil {
		t.Fatal("per-node TLS was overwritten")
	}
	var count int64
	db.Model(&model.NodeInbound{}).Where("node_id = 1").Count(&count)
	if count != 2 {
		t.Fatal("reapply duplicated remote inbounds")
	}
	db.Model(&model.ClientNodeInbound{}).Where("node_inbound_id = ?", first.Id).Count(&count)
	if count != 1 {
		t.Fatal("template update lost client binding")
	}
	template.Blueprints = json.RawMessage(`[]`)
	db.Save(&template)
	apply()
	db.First(&updated, first.Id)
	if updated.SourceTemplateId != 0 || updated.TemplateKey != "" {
		t.Fatal("removed blueprint did not detach its existing inbound")
	}
	db.Model(&model.ClientNodeInbound{}).Where("node_inbound_id = ?", first.Id).Count(&count)
	if count != 1 {
		t.Fatal("removed blueprint deleted working binding")
	}
}

func TestTemplateSaveIsExplicitAndFailedApplyRollsBack(t *testing.T) {
	db, template, node := templateFixture(t)
	node.TemplateId = template.Id
	db.Save(&node)
	if err := Save("nodetemplates", "edit", json.RawMessage(`{"id":1,"name":"changed","config":{"log":{"level":"debug"}},"blueprints":[]}`), "test"); err != nil {
		t.Fatal(err)
	}
	db.First(&node, node.Id)
	if !strings.Contains(string(node.Config), `"warn"`) {
		t.Fatal("template save changed a legacy node's current base")
	}
	template.Blueprints = json.RawMessage(`[{"key":"one","tag":"new-one","type":"vless","enable":true,"options":{"listen_port":14445}},{"key":"conflict","tag":"same","type":"vless","enable":true,"options":{"listen_port":14446}}]`)
	db.Save(&template)
	if err := db.Transaction(func(tx *gorm.DB) error { return applyTemplate(tx, &node, template.Id) }); err == nil {
		t.Fatal("conflicting template unexpectedly applied")
	}
	var count int64
	db.Model(&model.NodeInbound{}).Where("tag = ?", "new-one").Count(&count)
	if count != 0 {
		t.Fatal("failed template apply committed earlier partial rows")
	}
}

func TestTemplateNodeParametersAreResolvedInServerAndPublication(t *testing.T) {
	db, template, node := templateFixture(t)
	if err := db.Transaction(func(tx *gorm.DB) error { return applyTemplate(tx, &node, template.Id) }); err != nil {
		t.Fatal(err)
	}
	s, err := Compile(db, node)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(s.Deployment.Config), "{{NODE_") || !strings.Contains(string(s.Deployment.Config), "first.example") {
		t.Fatal("node address placeholder was not resolved")
	}
	if !strings.Contains(string(s.Inbounds[1].Options), "first.example") {
		t.Fatal("publication retained unresolved template data")
	}
	var stored model.NodeInbound
	db.Where("template_key = ?", "vless-slot").First(&stored)
	if !strings.Contains(string(stored.Options), "{{NODE_ADDRESS}}") {
		t.Fatal("runtime resolution mutated reusable source options")
	}
}

func TestSameTemplateCreatesIndependentIDsOnDifferentNodes(t *testing.T) {
	db, template, first := templateFixture(t)
	second := model.Node{Id: 2, Name: "two", Enable: true, LinkAddress: "second.example"}
	if err := db.Create(&second).Error; err != nil {
		t.Fatal(err)
	}
	for _, node := range []*model.Node{&first, &second} {
		if err := db.Transaction(func(tx *gorm.DB) error { return applyTemplate(tx, node, template.Id) }); err != nil {
			t.Fatal(err)
		}
	}
	var a, b model.NodeInbound
	db.Where("node_id = ? AND template_key = ?", first.Id, "vless-slot").First(&a)
	db.Where("node_id = ? AND template_key = ?", second.Id, "vless-slot").First(&b)
	if a.Id == b.Id || a.Id == 0 || b.Id == 0 || a.Tag != b.Tag {
		t.Fatal("shared template mixed node identities")
	}
	if err := db.Create(&model.ClientNodeInbound{ClientId: 1, NodeInboundId: a.Id}).Error; err != nil {
		t.Fatal(err)
	}
	s, err := Compile(db, second)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Deployment.Users) != 0 || !strings.Contains(string(s.Deployment.Config), "second.example") {
		t.Fatal("second node inherited another node's users/address")
	}
}

func TestBundleShowsPendingBeforeControllerRevisionAdvances(t *testing.T) {
	db, _, _ := fixture(t)
	runtime := &testRuntime{}
	manager := nodeagent.NewManager(1, nodeagent.FileStore{Directory: t.TempDir()}, runtime)
	t.Cleanup(func() { _ = manager.Close() })
	server, identity := controlServer(t, manager)
	if err := db.Model(&model.Node{}).Where("id = 1").Updates(map[string]interface{}{"address": server.URL, "control_ca": identity.CA, "control_certificate": identity.Certificate, "control_key": identity.Key}).Error; err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	bundle, err := Bundle()
	if err != nil {
		t.Fatal(err)
	}
	if bundle["nodes"].([]model.Node)[0].Pending {
		t.Fatal("acknowledged node is still pending")
	}
	if err := db.Model(&model.Node{}).Where("id = 1").Update("name", "saved-not-delivered").Error; err != nil {
		t.Fatal(err)
	}
	bundle, err = Bundle()
	if err != nil {
		t.Fatal(err)
	}
	value := bundle["nodes"].([]model.Node)[0]
	if !value.Pending || value.DesiredRevision != value.AppliedRevision {
		t.Fatal("saved intent was shown as applied before controller tick")
	}
	if err := Save("nodes", "edit", json.RawMessage(`{"id":1,"address":"https://127.0.0.1:19999"}`), "test"); err != nil {
		t.Fatal(err)
	}
	db.First(&value, 1)
	if value.LastSeen != 0 {
		t.Fatal("changing management identity retained old connection acknowledgement")
	}
}

func TestPublishedAddressCannotBeAURLOrIncludeAPort(t *testing.T) {
	for _, value := range []string{"server.example", "server-1.example", "192.0.2.10", "2001:db8::1", "[2001:db8::1]", "пример.рф"} {
		if !validPublishedAddress(value) {
			t.Fatal("valid published address rejected", value)
		}
	}
	for _, value := range []string{"https://server.example", "server.example:443", "server example", "server.example/path", "bad..example", "-bad.example", ""} {
		if validPublishedAddress(value) {
			t.Fatal("invalid published address accepted", value)
		}
	}
}
