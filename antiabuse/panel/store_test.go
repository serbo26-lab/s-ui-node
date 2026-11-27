package panel

import (
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	ipmodel "github.com/alireza0/s-ui/antiabuse/model"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "panel.db")), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sql, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sql.Close() })
	if err := db.AutoMigrate(&ipmodel.Settings{}, &ipmodel.GroupRule{}, &ipmodel.ClientRule{}, &ipmodel.Event{}); err != nil {
		t.Fatal(err)
	}
	s := NewStore(db)
	if err := s.Initialize(); err != nil {
		t.Fatal(err)
	}
	return s
}

func config(t *testing.T, s *Store) Configuration {
	t.Helper()
	v, err := s.Configuration()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDefaultConfigurationAndStaleSave(t *testing.T) {
	s := newStore(t)
	v := config(t, s)
	if v.Enabled || v.Revision != 1 || v.ActivitySeconds != 60 || v.TransitionSeconds != 120 || v.Groups == nil {
		t.Fatalf("defaults: %+v", v)
	}
	v.Enabled = true
	v.Groups = []ipmodel.GroupRule{{Group: "group", Limit: 4}}
	v.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	saved, err := s.SaveConfiguration(v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveConfiguration(v); !errors.Is(err, ErrConflict) {
		t.Fatal("stale form overwrote configuration")
	}
	if got := config(t, s); !reflect.DeepEqual(got, saved) {
		t.Fatalf("atomic configuration: %+v", got)
	}
	if err := s.Initialize(); err != nil {
		t.Fatal(err)
	}
	if got := config(t, s); !reflect.DeepEqual(got, saved) {
		t.Fatal("initialization overwrote restored settings")
	}
}

func TestFailedGroupWriteRollsBackEntireConfiguration(t *testing.T) {
	s := newStore(t)
	original := config(t, s)
	if err := s.db.Exec("CREATE TRIGGER reject_group BEFORE INSERT ON ip_control_groups BEGIN SELECT RAISE(ABORT, 'rejected'); END").Error; err != nil {
		t.Fatal(err)
	}
	v := original
	v.Enabled, v.ActivitySeconds = true, 90
	v.Groups = []ipmodel.GroupRule{{Group: "group", Limit: 4}}
	if _, err := s.SaveConfiguration(v); err == nil {
		t.Fatal("failed group write ignored")
	}
	if got := config(t, s); !reflect.DeepEqual(got, original) {
		t.Fatal("partial settings survived failed transaction")
	}
	rows, err := s.Events(0, 100)
	if err != nil || len(rows) != 0 {
		t.Fatal("rolled-back change entered event log")
	}
}

func TestClientOverridePreserveInheritAndRollback(t *testing.T) {
	s := newStore(t)
	limit := uint32(5)
	if err := SaveClientPolicy(s.db, 1, 100, &ipmodel.ClientPolicy{Limit: &limit}); err != nil {
		t.Fatal(err)
	}
	if err := SaveClientPolicy(s.db, 1, 100, nil); err != nil {
		t.Fatal(err)
	}
	var row ipmodel.ClientRule
	if err := s.db.First(&row, 1).Error; err != nil || row.Limit != 5 || row.CreatedAt != 100 {
		t.Fatal("omitted extension changed override")
	}
	failed := errors.New("client write failed")
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := SaveClientPolicy(tx, 1, 100, &ipmodel.ClientPolicy{}); err != nil {
			return err
		}
		return failed
	})
	if !errors.Is(err, failed) {
		t.Fatal(err)
	}
	if err := s.db.First(&row, 1).Error; err != nil || row.Limit != 5 {
		t.Fatal("policy escaped client rollback")
	}
	if err := SaveClientPolicy(s.db, 1, 100, &ipmodel.ClientPolicy{}); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := s.db.Model(&ipmodel.ClientRule{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatal("explicit inheritance did not remove override")
	}
}

func TestZeroOverrideAndClientDeletion(t *testing.T) {
	s := newStore(t)
	zero := uint32(0)
	if err := SaveClientPolicy(s.db, 1, 0, &ipmodel.ClientPolicy{Limit: &zero}); err != nil {
		t.Fatal(err)
	}
	var row ipmodel.ClientRule
	if err := s.db.First(&row, 1).Error; err != nil || row.Limit != 0 || row.CreatedAt != 0 {
		t.Fatal("explicit unlimited was not stored")
	}
	if err := DeleteClientPolicies(s.db, nil); err != nil {
		t.Fatal(err)
	}
	if err := DeleteClientPolicies(s.db, []uint{1}); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := s.db.Model(&ipmodel.ClientRule{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatal("deleted client's policy retained")
	}
}

func TestSavedEmptyGroupAndExactNames(t *testing.T) {
	s := newStore(t)
	if err := s.db.Exec("CREATE TABLE clients (id INTEGER PRIMARY KEY, `group` TEXT)").Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Exec("INSERT INTO clients (`group`) VALUES (?), (?), (?)", "group", "Group", "").Error; err != nil {
		t.Fatal(err)
	}
	v := config(t, s)
	v.Groups = []ipmodel.GroupRule{{Group: "empty", Limit: 4}}
	if _, err := s.SaveConfiguration(v); err != nil {
		t.Fatal(err)
	}
	names, err := s.GroupNames()
	if err != nil || !reflect.DeepEqual(names, []string{"Group", "empty", "group"}) {
		t.Fatalf("exact group names: %+v, %v", names, err)
	}
}

func TestConfigurationValidation(t *testing.T) {
	s := newStore(t)
	for _, edit := range []func(*Configuration){
		func(c *Configuration) { c.ActivitySeconds = 0 },
		func(c *Configuration) { c.TransitionSeconds = 10 },
		func(c *Configuration) { c.Groups = nil },
		func(c *Configuration) { c.Groups = []ipmodel.GroupRule{{Group: "group"}, {Group: "group"}} },
		func(c *Configuration) { c.Groups = []ipmodel.GroupRule{{Group: ""}} },
	} {
		v := config(t, s)
		edit(&v)
		if _, err := s.SaveConfiguration(v); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid configuration accepted")
		}
	}
}

func TestJournalPaginationAndRetention(t *testing.T) {
	s := newStore(t)
	now := time.Now()
	rows := []ipmodel.Event{{At: now.Add(-8 * 24 * time.Hour).Unix(), Code: "admission_changed"},
		{At: now.Unix(), Code: "admission_changed"}, {At: now.Unix(), Code: "configuration_changed"}}
	if err := s.db.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	page, err := s.Events(0, 1)
	if err != nil || len(page) != 1 || page[0].ID != rows[2].ID {
		t.Fatal("first journal page missing")
	}
	page, err = s.Events(page[0].ID, 1)
	if err != nil || len(page) != 1 || page[0].ID != rows[1].ID {
		t.Fatal("journal cursor repeated row")
	}
	if err := s.PruneEvents(now); err != nil {
		t.Fatal(err)
	}
	page, err = s.Events(0, 200)
	if err != nil || len(page) != 2 {
		t.Fatal("retention removed current events or retained old ones")
	}
}
