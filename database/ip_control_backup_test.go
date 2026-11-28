package database

import (
	"path/filepath"
	"testing"

	ipmodel "github.com/alireza0/s-ui/antiabuse/model"
)

func TestStandardBackupContainsCurrentIPPolicies(t *testing.T) {
	if err := InitDB(filepath.Join(t.TempDir(), "panel.db")); err != nil {
		t.Fatal(err)
	}
	rows := []any{
		&ipmodel.Settings{ID: 1, Revision: 7, Enabled: true, ActivitySeconds: 60, TransitionSeconds: 120},
		&ipmodel.GroupRule{Group: "group", Limit: 4},
		&ipmodel.ClientRule{ClientID: 1, CreatedAt: 100, Limit: 5},
		&ipmodel.Event{At: 100, Code: "configuration_changed"},
	}
	for _, row := range rows {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Model(&ipmodel.ClientRule{}).Where("client_id = 1").Update("limit", 6).Error; err != nil {
		t.Fatal(err)
	}
	contents, err := GetDb("stats,changes")
	if err != nil {
		t.Fatal(err)
	}
	restored := openBackup(t, contents)
	var settings ipmodel.Settings
	var policy ipmodel.ClientRule
	if err := restored.First(&settings, 1).Error; err != nil || settings.Revision != 7 || !settings.Enabled {
		t.Fatal("settings missing from ordinary backup")
	}
	if err := restored.First(&policy, 1).Error; err != nil || policy.Limit != 6 {
		t.Fatal("ordinary backup used stale client policy")
	}
	for _, table := range ipControlSchema() {
		var count int64
		if err := restored.Table(table.name).Count(&count).Error; err != nil || count != 1 {
			t.Fatalf("backup table %s: %d, %v", table.name, count, err)
		}
	}
}
