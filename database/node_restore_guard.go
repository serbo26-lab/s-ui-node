package database

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/alireza0/s-ui/database/model"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

var errNodeBackupStateStale = errors.New("node_backup_state_stale")

const restoreNodeIDWhere = "node_id = ?"

// A restore must not forget node intent already saved by this registration.
// The agent still enforces its own monotonic checkpoint, including when the
// destination is a new panel with no local history to compare.
func validateNodeRestoreState(path string) error {
	if !db.Migrator().HasTable(&model.Node{}) {
		return nil
	}
	var live []model.Node
	if err := db.Where("agent_protocol = ? AND control_epoch <> ''", 2).Find(&live).Error; err != nil {
		return err
	}
	if len(live) == 0 {
		return nil
	}
	candidate, err := gorm.Open(sqlite.Open("file:"+filepath.ToSlash(path)+"?mode=ro"), &gorm.Config{Logger: gormlogger.Discard})
	if err != nil {
		return err
	}
	pool, err := candidate.DB()
	if err != nil {
		return err
	}
	defer pool.Close()
	if !candidate.Migrator().HasTable(&model.Node{}) || !candidate.Migrator().HasTable(&model.NodeAccessState{}) {
		return errNodeBackupStateStale
	}
	for _, node := range live {
		if err := validateRestoredNodeState(candidate, node); err != nil {
			return err
		}
	}
	return nil
}

func validateRestoredNodeState(candidate *gorm.DB, live model.Node) error {
	var restored model.Node
	if err := candidate.First(&restored, live.Id).Error; err != nil {
		return errNodeBackupStateStale
	}
	if restored.ControlEpoch != live.ControlEpoch || restored.ControlCA != live.ControlCA || restored.ControlCertificate != live.ControlCertificate {
		return errNodeBackupStateStale
	}
	if restored.SettingsVersion < live.SettingsVersion || olderNodeCheckpoint(restored.DesiredRevision, live.DesiredRevision, live.AppliedRevision) {
		return errNodeBackupStateStale
	}
	if restored.DesiredRevision == live.DesiredRevision && !sameBackupJSON(restored.DesiredSnapshot, live.DesiredSnapshot) {
		return errNodeBackupStateStale
	}
	if err := validateRestoredAccessCheckpoint(candidate, live.Id); err != nil {
		return err
	}
	return validateRestoredCertificateCheckpoint(candidate, live.Id)
}

func olderNodeCheckpoint(archived, desired, applied uint64) bool {
	return archived < desired || archived < applied
}

func validateRestoredAccessCheckpoint(candidate *gorm.DB, nodeID uint) error {
	var current, archived model.NodeAccessState
	err := db.First(&current, restoreNodeIDWhere, nodeID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := candidate.First(&archived, restoreNodeIDWhere, nodeID).Error; err != nil {
		return errNodeBackupStateStale
	}
	if olderNodeCheckpoint(archived.DesiredRevision, current.DesiredRevision, current.AppliedRevision) {
		return errNodeBackupStateStale
	}
	if archived.DesiredRevision == current.DesiredRevision && !sameBackupJSON(archived.DesiredSnapshot, current.DesiredSnapshot) {
		return errNodeBackupStateStale
	}
	return nil
}

func validateRestoredCertificateCheckpoint(candidate *gorm.DB, nodeID uint) error {
	var current, archived model.NodeCertificateBinding
	err := db.First(&current, restoreNodeIDWhere, nodeID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := candidate.First(&archived, restoreNodeIDWhere, nodeID).Error; err != nil {
		return errNodeBackupStateStale
	}
	if olderNodeCheckpoint(archived.DesiredRevision, current.DesiredRevision, current.AppliedRevision) {
		return errNodeBackupStateStale
	}
	if archived.DesiredRevision == current.DesiredRevision && archived.DesiredFingerprint != current.DesiredFingerprint {
		return errNodeBackupStateStale
	}
	return nil
}

func sameBackupJSON(a, b json.RawMessage) bool {
	if len(a) == 0 || len(b) == 0 {
		return bytes.Equal(a, b)
	}
	if !json.Valid(a) || !json.Valid(b) {
		return false
	}
	var left, right any
	leftDecoder := json.NewDecoder(bytes.NewReader(a))
	rightDecoder := json.NewDecoder(bytes.NewReader(b))
	leftDecoder.UseNumber()
	rightDecoder.UseNumber()
	if leftDecoder.Decode(&left) != nil || rightDecoder.Decode(&right) != nil {
		return false
	}
	x, _ := json.Marshal(left)
	y, _ := json.Marshal(right)
	return bytes.Equal(x, y)
}
