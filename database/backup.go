package database

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/alireza0/s-ui/cmd/migration"
	"github.com/alireza0/s-ui/config"
	"github.com/alireza0/s-ui/logger"
	"github.com/alireza0/s-ui/util/common"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func GetDb(exclude string) ([]byte, error) {
	excluded := make(map[string]bool)
	for _, name := range strings.Split(exclude, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			excluded[name] = true
		}
	}

	// CreateTemp, not a hand-built timestamp: two downloads in the same period
	// used to render the same name and delete the file from under each other.
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, config.GetName()+"-backup-*.db")
	if err != nil {
		return nil, err
	}
	dbPath := tmp.Name()
	// SQLite opens the path itself; this handle only reserves the name.
	tmp.Close()
	defer os.Remove(dbPath)

	backupDb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	backupClosed := false
	closeBackup := func() {
		if backupClosed {
			return
		}
		backupClosed = true
		if sqlDB, e := backupDb.DB(); e == nil {
			_ = sqlDB.Close()
		}
	}
	defer closeBackup()

	// Same list InitDB migrates, so no table can be live but unbacked-up.
	if err = backupDb.AutoMigrate(schemaModels()...); err != nil {
		return nil, err
	}

	source, closeSource, err := backupReadSource()
	if err != nil {
		return nil, err
	}
	defer closeSource()
	err = source.Transaction(func(snapshot *gorm.DB) error {
		for _, t := range schema() {
			if excluded[t.name] {
				continue
			}
			if err := t.copyRows(snapshot, backupDb); err != nil {
				return common.NewErrorf("backing up %s: %v", t.name, err)
			}
		}
		return copyBackupSequences(snapshot, backupDb)
	})
	if err != nil {
		return nil, err
	}

	// Fold the WAL in, or the bytes read below miss whatever is still in it.
	if err = backupDb.Exec("PRAGMA wal_checkpoint(TRUNCATE);").Error; err != nil {
		return nil, err
	}
	closeBackup()

	return os.ReadFile(dbPath)
}

func ImportDB(file multipart.File) error {
	backupImportMu.Lock()
	defer backupImportMu.Unlock()
	var signature [4]byte
	if _, err := io.ReadFull(file, signature[:]); err != nil {
		return common.NewError("Invalid db file format")
	}
	if _, err := file.Seek(0, 0); err != nil {
		return err
	}
	if bytes.Equal(signature[:], []byte{'P', 'K', 3, 4}) {
		size, err := file.Seek(0, io.SeekEnd)
		if err != nil {
			return err
		}
		body, key, err := readFullBackup(file, size)
		if err != nil {
			return err
		}
		return importSQLite(backupMemoryFile{bytes.NewReader(body)}, key, len(key) > 0)
	}
	return importSQLite(file, nil, false)
}

func importSQLite(file multipart.File, suppliedKey []byte, replaceKey bool) error {
	valid, err := IsSQLiteDB(file)
	if err != nil {
		return err
	}
	if !valid {
		return common.NewError("Invalid db file format")
	}
	if _, err = file.Seek(0, 0); err != nil {
		return err
	}
	dbPath := config.GetDBPath()
	tempPath := dbPath + ".temp"
	if err = os.Remove(tempPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	tempFile, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	copied, copyErr := io.Copy(tempFile, io.LimitReader(file, backupLimit+1))
	closeErr := tempFile.Close()
	defer os.Remove(tempPath)
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if copied > backupLimit {
		return common.NewError("Backup file too large")
	}
	if err = validateImport(tempPath); err != nil {
		return err
	}
	keyPath := filepath.Join(filepath.Dir(dbPath), "node-provision.key")
	oldKey, keyErr := os.ReadFile(keyPath)
	if keyErr != nil && !os.IsNotExist(keyErr) {
		return keyErr
	}
	selectedKey := oldKey
	if replaceKey {
		selectedKey = suppliedKey
	}
	if err = validateNodeBackupKey(tempPath, selectedKey); err != nil {
		return err
	}
	fallbackPath := fmt.Sprintf("%s.backup-%d", dbPath, time.Now().UnixNano())
	journal := backupPairJournal{Version: 1, Fallback: filepath.Base(fallbackPath), OldKey: keyErr == nil}
	if replaceKey {
		if journal.OldKey {
			if err = backupWritePrivate(fallbackPath+".key", oldKey); err != nil {
				return err
			}
		}
		if err = writePairJournal(dbPath, journal); err != nil {
			return err
		}
	}
	if sqlDB, e := db.DB(); e == nil {
		_ = db.Exec("PRAGMA wal_checkpoint(TRUNCATE);").Error
		_ = sqlDB.Close()
	}
	removeSidecars(dbPath)
	if err = os.Rename(dbPath, fallbackPath); err != nil {
		if replaceKey {
			_ = os.Remove(pairJournalPath(dbPath))
		}
		reopen(dbPath)
		return err
	}
	rollback := func() {
		if replaceKey {
			journal.Ready = false
			if e := writePairJournal(dbPath, journal); e != nil {
				logger.Error("restore pair journal failed")
				return
			}
			if e := recoverBackupPair(dbPath); e != nil {
				logger.Error("restore pair rollback failed")
				return
			}
			reopen(dbPath)
		} else {
			restoreFallback(dbPath, fallbackPath)
		}
	}
	if replaceKey {
		if err = backupWritePrivate(keyPath, suppliedKey); err != nil {
			rollback()
			return err
		}
	}
	if err = os.Rename(tempPath, dbPath); err != nil {
		rollback()
		return err
	}
	if replaceKey {
		journal.Ready = true
		if err = writePairJournal(dbPath, journal); err != nil {
			rollback()
			return err
		}
	}
	if err = migration.MigrateDb(); err != nil {
		rollback()
		return common.NewErrorf("Error migrating db: %v", err)
	}
	if err = InitDB(dbPath); err != nil {
		rollback()
		return common.NewErrorf("Error initialising imported db: %v", err)
	}
	logger.Info("database imported; previous database kept at ", fallbackPath)
	return SendSighup()
}

// validateImport rejects a SQLite file that is not an s-ui database, before it
// can replace the live one.
func validateImport(path string) error {
	candidate, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: gormlogger.Discard})
	if err != nil {
		return common.NewErrorf("Error checking db: %v", err)
	}
	defer func() {
		if sqlDB, e := candidate.DB(); e == nil {
			_ = sqlDB.Close()
		}
	}()

	// settings carries the schema version and session secret; without clients
	// and inbounds it is not a panel backup whatever else it holds.
	for _, required := range []string{"settings", "clients", "inbounds"} {
		if !candidate.Migrator().HasTable(required) {
			return common.NewErrorf("Not an s-ui database: table %q is missing", required)
		}
	}
	return nil
}

// removeSidecars drops the -wal and -shm files belonging to path; they describe
// the database being replaced, not the one taking its place.
func removeSidecars(path string) {
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
			logger.Warning("unable to remove ", path+suffix, ": ", err)
		}
	}
}

// reopen restores the connection pool after an import gave up.
func reopen(path string) {
	if err := InitDB(path); err != nil {
		logger.Error("unable to reopen the database after a failed import: ", err)
	}
}

func restoreFallback(dbPath, fallbackPath string) {
	removeSidecars(dbPath)
	if err := os.Rename(fallbackPath, dbPath); err != nil {
		logger.Error("unable to restore the database after a failed import: ", err)
		return
	}
	reopen(dbPath)
}

func IsSQLiteDB(file io.Reader) (bool, error) {
	signature := []byte("SQLite format 3\x00")
	buf := make([]byte, len(signature))
	// ReadFull: a single Read may return short and compare a partial buffer.
	if _, err := io.ReadFull(file, buf); err != nil {
		return false, err
	}
	return bytes.Equal(buf, signature), nil
}

func SendSighup() error {
	// Get the current process
	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}

	// Send SIGHUP to the current process
	go func() {
		time.Sleep(3 * time.Second)
		if runtime.GOOS == "windows" {
			err = process.Kill()
		} else {
			err = process.Signal(syscall.SIGHUP)
		}
		if err != nil {
			logger.Error("send signal SIGHUP failed:", err)
		}
	}()
	return nil
}
