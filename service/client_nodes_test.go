package service

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"gorm.io/gorm"
)

func nodeAssignmentDB(t *testing.T) *gorm.DB {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "nodes.db")); err != nil {
		t.Fatal(err)
	}
	db := database.GetDB()
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.Create(&model.Inbound{Id: 21, Type: "direct", Tag: "local", Enable: true, Options: json.RawMessage(`{"listen_port":12345}`)}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.NodeInbound{Id: 1, NodeId: 1, Tag: "remote", Type: "vless", Enable: true, Options: json.RawMessage(`{}`)}).Error; err != nil {
		t.Fatal(err)
	}
	return db
}

func TestClientNodeInboundIDsAreIndependentAndOmittedFieldPreserves(t *testing.T) {
	db := nodeAssignmentDB(t)
	s := &ClientService{}
	body := json.RawMessage(`{"name":"one","enable":true,"config":{},"inbounds":[21],"nodeinbounds":[1],"links":[]}`)
	if err := db.Transaction(func(tx *gorm.DB) error { _, err := s.Save(tx, "new", body, "localhost"); return err }); err != nil {
		t.Fatal(err)
	}
	var client model.Client
	if err := db.First(&client).Error; err != nil {
		t.Fatal(err)
	}
	if string(client.Inbounds) != "[21]" {
		t.Fatalf("local IDs changed: %s", client.Inbounds)
	}
	loaded, err := s.Get("1")
	if err != nil {
		t.Fatal(err)
	}
	if len(*loaded) != 1 || string((*loaded)[0].NodeInbounds) != "[1]" {
		t.Fatalf("wrong remote IDs: %+v", loaded)
	}
	var decoded map[string]interface{}
	b, _ := json.Marshal((*loaded)[0])
	_ = json.Unmarshal(b, &decoded)
	if _, ok := decoded["nodeinbounds"]; !ok {
		t.Fatal("canonical field missing")
	}
	if _, ok := decoded["nodeInbounds"]; ok {
		t.Fatal("wrong field spelling")
	}
	body = json.RawMessage(`{"id":1,"name":"one","enable":true,"config":{},"inbounds":[21],"links":[]}`)
	if err := db.Transaction(func(tx *gorm.DB) error { _, err := s.Save(tx, "edit", body, "localhost"); return err }); err != nil {
		t.Fatal(err)
	}
	var count int64
	db.Model(&model.ClientNodeInbound{}).Where("client_id = ?", 1).Count(&count)
	if count != 1 {
		t.Fatal("legacy request erased remote assignments")
	}
	body = json.RawMessage(`{"id":1,"name":"one","enable":true,"config":{},"inbounds":[21],"nodeinbounds":[],"links":[]}`)
	if err := db.Transaction(func(tx *gorm.DB) error { _, err := s.Save(tx, "edit", body, "localhost"); return err }); err != nil {
		t.Fatal(err)
	}
	db.Model(&model.ClientNodeInbound{}).Count(&count)
	if count != 0 {
		t.Fatal("explicit empty list did not clear remote assignments")
	}
	db.First(&client, 1)
	if string(client.Inbounds) != "[21]" {
		t.Fatal("clearing remote assignments changed local IDs")
	}
}

func TestLocalInboundIDCannotBeAssignedAsNodeInbound(t *testing.T) {
	db := nodeAssignmentDB(t)
	body := json.RawMessage(`{"name":"wrong","enable":true,"config":{},"inbounds":[21],"nodeinbounds":[21],"links":[]}`)
	err := db.Transaction(func(tx *gorm.DB) error { _, err := (&ClientService{}).Save(tx, "new", body, "localhost"); return err })
	if err == nil {
		t.Fatal("local inbound ID accepted as remote")
	}
	var count int64
	db.Model(&model.Client{}).Count(&count)
	if count != 0 {
		t.Fatal("invalid remote assignment committed client")
	}
}

func TestEqualNumericLocalAndRemoteIDsRemainSeparate(t *testing.T) {
	db := nodeAssignmentDB(t)
	if err := db.Create(&model.Inbound{Id: 1, Type: "direct", Tag: "same-integer", Enable: true, Options: json.RawMessage(`{}`)}).Error; err != nil {
		t.Fatal(err)
	}
	body := json.RawMessage(`{"name":"same","enable":true,"config":{},"inbounds":[1],"nodeinbounds":[1],"links":[]}`)
	if err := db.Transaction(func(tx *gorm.DB) error { _, err := (&ClientService{}).Save(tx, "new", body, "localhost"); return err }); err != nil {
		t.Fatal(err)
	}
	clients, err := (&ClientService{}).Get("1")
	if err != nil {
		t.Fatal(err)
	}
	if string((*clients)[0].Inbounds) != "[1]" || string((*clients)[0].NodeInbounds) != "[1]" {
		t.Fatal("equal integers crossed namespace")
	}
	var config map[string]map[string]interface{}
	_ = json.Unmarshal((*clients)[0].Config, &config)
	if config["vless"]["uuid"] == nil {
		t.Fatal("missing node credentials were not initialized")
	}
}

func TestNodeAssignmentsBulkAndInvalidLists(t *testing.T) {
	db := nodeAssignmentDB(t)
	s := &ClientService{}
	save := func(action, value string) error {
		return db.Transaction(func(tx *gorm.DB) error { _, err := s.Save(tx, action, json.RawMessage(value), "localhost"); return err })
	}
	if err := save("addbulk", `[{"name":"first","enable":true,"config":{},"inbounds":[21],"nodeinbounds":[1],"links":[]},{"name":"second","enable":true,"config":{},"inbounds":[21],"nodeinbounds":[1],"links":[]}]`); err != nil {
		t.Fatal(err)
	}
	clients, err := s.Get("1,2")
	if err != nil {
		t.Fatal(err)
	}
	if len(*clients) != 2 {
		t.Fatal("bulk clients missing")
	}
	for _, client := range *clients {
		if string(client.Inbounds) != "[21]" || string(client.NodeInbounds) != "[1]" {
			t.Fatal("bulk mixed namespaces")
		}
	}
	if err := save("editbulk", `[{"id":1,"name":"first","enable":true,"inbounds":[21],"nodeinbounds":[],"links":[]},{"id":2,"name":"second","enable":true,"inbounds":[21],"links":[]}]`); err != nil {
		t.Fatal(err)
	}
	clients, err = s.Get("1,2")
	if err != nil {
		t.Fatal(err)
	}
	if string((*clients)[0].NodeInbounds) != "[]" || string((*clients)[1].NodeInbounds) != "[1]" {
		t.Fatal("bulk omission/clear semantics lost")
	}
	for _, invalid := range []string{"null", "[0]", "[1,1]", "[\"1\"]", "[1.1]", "[-1]"} {
		body := `{"name":"invalid","enable":true,"config":{},"inbounds":[21],"links":[],"nodeinbounds":` + invalid + `}`
		if err := save("new", body); err == nil {
			t.Fatalf("accepted invalid node list %s", invalid)
		}
	}
	if err := save("delbulk", `[1,2]`); err != nil {
		t.Fatal(err)
	}
	var count int64
	db.Model(&model.ClientNodeInbound{}).Count(&count)
	if count != 0 {
		t.Fatal("bulk deletion left remote assignments")
	}
}

func TestQuickDisableReenablePersistsNodeSessionRevocation(t *testing.T) {
	db := nodeAssignmentDB(t)
	s := &ClientService{}
	save := func(action string, value interface{}) {
		t.Helper()
		body, _ := json.Marshal(value)
		if err := db.Transaction(func(tx *gorm.DB) error { _, err := s.Save(tx, action, body, "localhost"); return err }); err != nil {
			t.Fatal(err)
		}
	}
	save("new", map[string]interface{}{"name": "epoch", "enable": true, "config": map[string]interface{}{}, "inbounds": []uint{21}, "nodeinbounds": []uint{1}, "links": []interface{}{}})
	clients, err := s.Get("1")
	if err != nil {
		t.Fatal(err)
	}
	client := (*clients)[0]
	originalConfig := string(client.Config)
	client.Enable = false
	save("edit", client)
	clients, _ = s.Get("1")
	disabled := (*clients)[0]
	client = disabled
	client.Enable = true
	save("edit", client)
	clients, _ = s.Get("1")
	enabled := (*clients)[0]
	if disabled.NodeGeneration == 0 || enabled.NodeGeneration <= disabled.NodeGeneration {
		t.Fatal("quick disable/re-enable was coalesced without a persisted node access change")
	}
	if string(enabled.Config) != originalConfig {
		t.Fatal("session revocation changed customer credentials")
	}
	before := enabled.NodeGeneration
	save("edit", enabled)
	clients, _ = s.Get("1")
	if (*clients)[0].NodeGeneration != before {
		t.Fatal("idempotent edit unnecessarily changed node access epoch")
	}
}
