package database

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/alireza0/s-ui/database/model"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestNodesMigrationAndBackupPreserveSeparateAssignments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.AutoMigrate(&model.Client{}, &model.Inbound{}); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Create(&model.Inbound{Id: 21, Tag: "local", Type: "vless", Options: json.RawMessage(`{}`)}).Error; err != nil {
		t.Fatal(err)
	}
	if err := legacy.Create(&model.Client{Id: 1, Name: "existing", Enable: true, Inbounds: json.RawMessage(`[21]`), Config: json.RawMessage(`{}`), Links: json.RawMessage(`[]`)}).Error; err != nil {
		t.Fatal(err)
	}
	if err := legacy.Migrator().DropColumn(&model.Client{}, "NodeGeneration"); err != nil {
		t.Fatal(err)
	}
	oldSQL, _ := legacy.DB()
	_ = oldSQL.Close()
	if err := InitDB(path); err != nil {
		t.Fatal(err)
	}
	liveSQL, _ := db.DB()
	t.Cleanup(func() { _ = liveSQL.Close() })
	if !db.Migrator().HasColumn(&model.Client{}, "NodeGeneration") {
		t.Fatal("old client schema was not migrated")
	}
	if err := db.Model(&model.Client{}).Where("id = 1").Update("node_generation", 7).Error; err != nil {
		t.Fatal(err)
	}
	for _, row := range []interface{}{
		&model.NodeTemplate{Id: 1, Name: "base", Config: json.RawMessage(`{}`), Blueprints: json.RawMessage(`[{"key":"stable-slot","tag":"node","type":"vless","enable":true,"options":{"listen_port":14443}}]`)},
		&model.Node{Id: 1, Name: "node", Enable: true, ControlKey: "private-backup-key", Config: json.RawMessage(`{"log":{"level":"warn"}}`), TemplateBase: json.RawMessage(`{"log":{"level":"error"}}`), TLSStatus: json.RawMessage(`{"revision":7,"certificates":[{"state":"ready"}]}`), RejectedRevision: 9, AppliedRevision: 7, AppliedSnapshot: json.RawMessage(`{"private":"last-good"}`)},
		&model.NodeInbound{Id: 1, NodeId: 1, Tag: "local", Type: "vless", Enable: true, Options: json.RawMessage(`{"listen_port":14443}`), SourceTemplateId: 1, TemplateKey: "stable-slot", TemplateBase: json.RawMessage(`{"options":{"listen_port":14443}}`)},
		&model.ClientNodeInbound{ClientId: 1, NodeInboundId: 1},
	} {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	contents, err := GetDb("")
	if err != nil {
		t.Fatal(err)
	}
	restored := openBackup(t, contents)
	var client model.Client
	var node model.Node
	var binding model.ClientNodeInbound
	if err := restored.First(&client, 1).Error; err != nil {
		t.Fatal(err)
	}
	if err := restored.First(&node, 1).Error; err != nil {
		t.Fatal(err)
	}
	if err := restored.First(&binding).Error; err != nil {
		t.Fatal(err)
	}
	if string(client.Inbounds) != "[21]" || binding.NodeInboundId != 1 || binding.ClientId != 1 || client.NodeGeneration != 7 {
		t.Fatal("migration/backup mixed local and remote ID namespaces")
	}
	if node.ControlKey != "private-backup-key" || node.AppliedRevision != 7 || string(node.AppliedSnapshot) != `{"private":"last-good"}` {
		t.Fatal("backup omitted private node state")
	}
	if node.RejectedRevision != 9 || string(node.TemplateBase) != `{"log":{"level":"error"}}` || string(node.Config) != `{"log":{"level":"warn"}}` {
		t.Fatal("backup omitted node overrides/base/rejection state")
	}
	if string(node.TLSStatus) != `{"revision":7,"certificates":[{"state":"ready"}]}` {
		t.Fatal("backup omitted certificate observations")
	}
	var template model.NodeTemplate
	var inbound model.NodeInbound
	if err := restored.First(&template, 1).Error; err != nil {
		t.Fatal(err)
	}
	if err := restored.First(&inbound, 1).Error; err != nil {
		t.Fatal(err)
	}
	if len(template.Blueprints) == 0 || inbound.TemplateKey != "stable-slot" || inbound.SourceTemplateId != 1 || len(inbound.TemplateBase) == 0 {
		t.Fatal("backup omitted stable template binding/base")
	}
}
