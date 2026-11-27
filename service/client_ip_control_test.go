package service

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	ipmodel "github.com/alireza0/s-ui/antiabuse/model"
	"github.com/alireza0/s-ui/database/model"
	"github.com/mattn/go-sqlite3"

	"gorm.io/gorm"
)

func saveIPClient(t *testing.T, db *gorm.DB, action string, value any) error {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return db.Transaction(func(tx *gorm.DB) error {
		_, err := (&ClientService{}).Save(tx, action, body, "localhost")
		return err
	})
}

func ipClientPayload() map[string]any {
	return map[string]any{"name": "client", "enable": true, "config": map[string]any{},
		"inbounds": []uint{}, "nodes": []uint{}, "links": []any{}, "ip_control": map[string]any{"limit": 5}}
}

func getIPClient(t *testing.T) model.Client {
	t.Helper()
	clients, err := (&ClientService{}).Get("1")
	if err != nil || len(*clients) != 1 {
		t.Fatalf("client read: %v", err)
	}
	return (*clients)[0]
}

func TestClientIPPolicySharesSaveAndPreservesOmittedExtension(t *testing.T) {
	db := clientTestDB(t)
	if err := saveIPClient(t, db, "new", ipClientPayload()); err != nil {
		t.Fatal(err)
	}
	client := getIPClient(t)
	if client.IPControl == nil || client.IPControl.Limit == nil || *client.IPControl.Limit != 5 {
		t.Fatal("saved override not hydrated")
	}
	client.IPControl = nil
	client.Remark = "updated"
	if err := saveIPClient(t, db, "edit", client); err != nil {
		t.Fatal(err)
	}
	client = getIPClient(t)
	if client.IPControl.Limit == nil || *client.IPControl.Limit != 5 || client.Remark != "updated" {
		t.Fatal("ordinary client edit changed IP override")
	}
	client.IPControl = &ipmodel.ClientPolicy{}
	if err := saveIPClient(t, db, "edit", client); err != nil {
		t.Fatal(err)
	}
	if getIPClient(t).IPControl.Limit != nil {
		t.Fatal("explicit inheritance not saved")
	}
}

func TestClientCloneAndBulkOperationsKeepIndependentIPPolicies(t *testing.T) {
	db := clientTestDB(t)
	if err := saveIPClient(t, db, "new", ipClientPayload()); err != nil {
		t.Fatal(err)
	}
	clone := getIPClient(t)
	clone.Id, clone.Name = 0, "clone"
	if err := saveIPClient(t, db, "new", clone); err != nil {
		t.Fatal(err)
	}
	zero, inherited := ipClientPayload(), ipClientPayload()
	zero["name"], zero["ip_control"] = "bulk-zero", map[string]any{"limit": 0}
	inherited["name"], inherited["ip_control"] = "bulk-inherit", map[string]any{"limit": nil}
	if err := saveIPClient(t, db, "addbulk", []any{zero, inherited}); err != nil {
		t.Fatal(err)
	}
	clients, err := (&ClientService{}).Get("1,2,3,4")
	if err != nil || len(*clients) != 4 {
		t.Fatal("bulk clients not returned", err)
	}
	byID := map[uint]model.Client{}
	for _, client := range *clients {
		byID[client.Id] = client
	}
	if *byID[1].IPControl.Limit != 5 || *byID[2].IPControl.Limit != 5 || *byID[3].IPControl.Limit != 0 || byID[4].IPControl.Limit != nil {
		t.Fatal("clone or bulk save changed independent policy values")
	}
	first, second := byID[1], byID[2]
	first.Name, first.Group, first.IPControl = "renamed", "moved", nil
	second.IPControl = &ipmodel.ClientPolicy{}
	if err := saveIPClient(t, db, "editbulk", []model.Client{first, second}); err != nil {
		t.Fatal(err)
	}
	clients, err = (&ClientService{}).Get("1,2")
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range *clients {
		if client.Id == 1 && (client.Name != "renamed" || client.Group != "moved" || client.IPControl.Limit == nil || *client.IPControl.Limit != 5) {
			t.Fatal("rename, group change or omitted bulk extension lost the original policy")
		}
		if client.Id == 2 && client.IPControl.Limit != nil {
			t.Fatal("clone inheritance changed the source policy")
		}
	}
	if err := saveIPClient(t, db, "delbulk", []uint{2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	var rules []ipmodel.ClientRule
	if err := db.Find(&rules).Error; err != nil || len(rules) != 1 || rules[0].ClientID != 1 || rules[0].Limit != 5 {
		t.Fatal("bulk deletion left an orphan IP policy", err)
	}
}

func TestClientPolicyFailureRollsBackClient(t *testing.T) {
	db := clientTestDB(t)
	if err := db.Exec("CREATE TRIGGER reject_ip_policy BEFORE INSERT ON ip_control_clients BEGIN SELECT RAISE(ABORT, 'rejected'); END").Error; err != nil {
		t.Fatal(err)
	}
	if err := saveIPClient(t, db, "new", ipClientPayload()); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("policy persistence failure not reported: %v", err)
	}
	var count int64
	if err := db.Model(&model.Client{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatal("client survived failed policy save")
	}
}

func TestClientDeletionRemovesIPOverride(t *testing.T) {
	db := clientTestDB(t)
	if err := saveIPClient(t, db, "new", ipClientPayload()); err != nil {
		t.Fatal(err)
	}
	if err := saveIPClient(t, db, "del", uint(1)); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := db.Model(&ipmodel.ClientRule{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatal("deleted client's override retained")
	}
}

func TestConfigSaveReportsCommitFailure(t *testing.T) {
	db := clientTestDB(t)
	sql, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sql.SetMaxOpenConns(1)
	for _, statement := range []string{
		"PRAGMA foreign_keys = ON",
		"CREATE TABLE commit_parent (id INTEGER PRIMARY KEY)",
		"CREATE TABLE commit_child (parent_id INTEGER REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED)",
		"CREATE TRIGGER defer_client_failure AFTER INSERT ON clients BEGIN INSERT INTO commit_child(parent_id) VALUES (999); END",
	} {
		if err := db.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
	body, err := json.Marshal(ipClientPayload())
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&ConfigService{}).Save("clients", "new", body, "", "admin", "localhost")
	var sqliteError sqlite3.Error
	if !errors.As(err, &sqliteError) || sqliteError.ExtendedCode != sqlite3.ErrConstraintForeignKey {
		t.Fatalf("deferred commit failure not reported: %v", err)
	}
	var count int64
	if err := db.Model(&ipmodel.ClientRule{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatal("IP policy survived failed client commit")
	}
}
