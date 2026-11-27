package app

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/alireza0/s-ui/antiabuse/engine"
	ipmodel "github.com/alireza0/s-ui/antiabuse/model"
	ipcontrol "github.com/alireza0/s-ui/antiabuse/panel"
	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/database/model"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func controlStore(t *testing.T, limit uint32) (*ipcontrol.Store, func()) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "panel.db")), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	closeDB := func() { _ = connection.Close() }
	t.Cleanup(closeDB)
	if err := db.AutoMigrate(&ipmodel.Settings{}, &ipmodel.GroupRule{}, &ipmodel.ClientRule{}, &ipmodel.Event{},
		&model.Client{}, &model.Inbound{}, &model.ClientNode{}, &model.Node{}, &model.NodeAccessState{}); err != nil {
		t.Fatal(err)
	}
	store := ipcontrol.NewStore(db)
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	config, err := store.Configuration()
	if err != nil {
		t.Fatal(err)
	}
	config.Groups = []ipmodel.GroupRule{{Group: "group", Limit: limit}}
	if _, err := store.SaveConfiguration(config); err != nil {
		t.Fatal(err)
	}
	return store, closeDB
}

func TestIPControlRestartUsesRestoredDatabaseAndNewScope(t *testing.T) {
	runtime, err := ipruntime.New(engine.DefaultProfile(), nil)
	if err != nil {
		t.Fatal(err)
	}
	state := &ipControlState{runtime: runtime}
	t.Cleanup(state.stop)
	first, closeFirst := controlStore(t, 4)
	if err := state.start(first, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	scope := controlScope(t, state.controller)
	state.stop()
	closeFirst()
	restored, _ := controlStore(t, 5)
	if err := state.start(restored, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if controlScope(t, state.controller) == scope {
		t.Fatal("restored controller reused its former scope")
	}
	config, err := ipcontrol.Current().Configuration()
	if err != nil || len(config.Groups) != 1 || config.Groups[0].Limit != 5 {
		t.Fatal("restored controller retained the closed database", err)
	}
	state.stop()
	if ipcontrol.Current() != nil {
		t.Fatal("stopped coordinator remained registered")
	}
}

func controlScope(t *testing.T, controller *ipcontrol.Controller) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if scope := controller.Status(nil).Scope; scope != "" {
			return scope
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("coordinator did not initialize")
	return ""
}
