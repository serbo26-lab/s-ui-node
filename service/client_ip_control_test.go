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
