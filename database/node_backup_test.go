package database

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/alireza0/s-ui/config"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/logger"
	"github.com/op/go-logging"
)

func backupFixtureSeal(t *testing.T, key []byte) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte("fixture-secret"), []byte("s-ui-node-provision-v1")))
}
func nodeBackupFixture(t *testing.T) (string, []byte) {
	t.Helper()
	folder := t.TempDir()
	t.Setenv("SUI_DB_FOLDER", folder)
	path := filepath.Join(folder, "s-ui.db")
	if err := InitDB(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool, _ := db.DB(); pool.Close() })
	key := bytes.Repeat([]byte{0x31}, 32)
	if err := os.WriteFile(filepath.Join(folder, "node-provision.key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.NodeDNSProfile{Name: "Fixture", AuthType: "token", Zones: json.RawMessage(`[]`), Secret: backupFixtureSeal(t, key)}).Error; err != nil {
		t.Fatal(err)
	}
	return path, key
}

func TestFullBackupCarriesCorrectKeyAndRejectsMissingOrWrongKey(t *testing.T) {
	path, key := nodeBackupFixture(t)
	if _, err := GetFullBackup("client_nodes"); err == nil {
		t.Fatal("incomplete node export called full backup")
	}
	archive, err := GetFullBackup("stats,changes")
	if err != nil {
		t.Fatal(err)
	}
	body, restoredKey, err := readFullBackup(bytes.NewReader(archive), int64(len(archive)))
	if err != nil || !bytes.Equal(restoredKey, key) {
		t.Fatal("archive roundtrip", err)
	}
	if err = validateBackupBytes(body, bytes.Repeat([]byte{0x32}, 32)); err == nil {
		t.Fatal("wrong key accepted")
	}
	if err = os.Remove(filepath.Join(filepath.Dir(path), "node-provision.key")); err != nil {
		t.Fatal(err)
	}
	if err = ImportDB(backupMemoryFile{bytes.NewReader(body)}); err == nil {
		t.Fatal("DB-only import silently lost encrypted node state")
	}
	if _, err = os.Stat(filepath.Join(filepath.Dir(path), "node-provision.key")); !os.IsNotExist(err) {
		t.Fatal("missing key regenerated")
	}
	var count int64
	if err = db.Model(&model.NodeDNSProfile{}).Count(&count).Error; err != nil || count != 1 {
		t.Fatal("rejected import damaged current DB", err)
	}
}

func TestFullBackupValidatesAllSecretsAndArchiveNames(t *testing.T) {
	_, key := nodeBackupFixture(t)
	if err := db.Create(&model.NodeJob{Id: "fixture-job", Plan: "not-a-valid-cipher"}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := GetFullBackup(""); err == nil {
		t.Fatal("later cipher column corruption missed")
	}
	db.Delete(&model.NodeJob{}, "id = ?", "fixture-job")
	archive, err := GetFullBackup("")
	if err != nil {
		t.Fatal(err)
	}
	dbBody, _, err := readFullBackup(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../panel.db", "nested/panel.db", "node-provision.key"} {
		var out bytes.Buffer
		z := zip.NewWriter(&out)
		w, _ := z.Create(name)
		w.Write(append(key, 'x'))
		z.Close()
		if _, _, err := readFullBackup(bytes.NewReader(out.Bytes()), int64(out.Len())); err == nil {
			t.Fatal("invalid archive member accepted", name)
		}
	}
	if len(dbBody) == 0 {
		t.Fatal("empty DB")
	}
}

func TestBackupPreservesDeletedIDHighWater(t *testing.T) {
	_, _ = nodeBackupFixture(t)
	high := model.Client{Id: 9000, Name: "deleted", Config: json.RawMessage(`{}`)}
	if err := db.Create(&high).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Delete(&high).Error; err != nil {
		t.Fatal(err)
	}
	contents, err := GetDb("")
	if err != nil {
		t.Fatal(err)
	}
	restored := openBackup(t, contents)
	next := model.Client{Name: "new", Config: json.RawMessage(`{}`)}
	if err = restored.Create(&next).Error; err != nil {
		t.Fatal(err)
	}
	if next.Id <= 9000 {
		t.Fatal("backup reused a deleted identity")
	}
}

func TestInterruptedDBKeyPairRestoresOldPairBeforeOpen(t *testing.T) {
	path, key := nodeBackupFixture(t)
	pool, _ := db.DB()
	pool.Close()
	files, err := openRestoreFiles(path)
	if err != nil {
		t.Fatal(err)
	}
	defer files.root.Close()
	fallback := files.database + ".backup-fixture"
	if err := files.root.Rename(files.database, fallback); err != nil {
		t.Fatal(err)
	}
	if err := files.writePrivate(backupKeyName, bytes.Repeat([]byte{0x32}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("interrupted replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := files.writeJournal(backupPairJournal{Version: 1, Fallback: fallback, OldKey: true}); err != nil {
		t.Fatal(err)
	}
	if err := OpenDB(path); !os.IsNotExist(err) {
		t.Fatalf("want recovery to stop on missing saved key, got %v", err)
	}
	if _, err := files.root.Stat(fallback); err != nil {
		t.Fatal("failed recovery consumed the saved database", err)
	}
	if err := files.writePrivate(fallback+".key", key); err != nil {
		t.Fatal(err)
	}
	if err := InitDB(path); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(filepath.Join(filepath.Dir(path), "node-provision.key"))
	if err != nil || !bytes.Equal(restored, key) {
		t.Fatal("key pair not restored", err)
	}
	if err = validateNodeBackupKey(path, key); err != nil {
		t.Fatal(err)
	}
	if _, err = files.root.Stat(files.journalName()); !os.IsNotExist(err) {
		t.Fatal("rollback journal not completed")
	}
}

func TestReadyPairWithWrongKeyFailsClosed(t *testing.T) {
	path, key := nodeBackupFixture(t)
	pool, _ := db.DB()
	pool.Close()
	files, err := openRestoreFiles(path)
	if err != nil {
		t.Fatal(err)
	}
	defer files.root.Close()
	if err := files.writeJournal(backupPairJournal{Version: 1, Fallback: files.database + ".backup-fixture", OldKey: true, Ready: true}); err != nil {
		t.Fatal(err)
	}
	if err := files.writePrivate(backupKeyName, bytes.Repeat([]byte{0x32}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := OpenDB(path); err == nil {
		t.Fatal("opened mismatched ready pair")
	}
	if err := files.writePrivate(backupKeyName, key); err != nil {
		t.Fatal(err)
	}
	if err := InitDB(path); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreLegacySQLiteAndFullArchive(t *testing.T) {
	logger.InitLogger(logging.ERROR)
	for _, format := range []string{"sqlite", "zip"} {
		t.Run(format, func(t *testing.T) {
			path, key := nodeBackupFixture(t)
			keyPath := filepath.Join(filepath.Dir(path), backupKeyName)
			version := config.GetVersion()
			if format == "sqlite" {
				version = "1.6.7"
				if err := db.Delete(&model.NodeDNSProfile{}, "name = ?", "Fixture").Error; err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(keyPath); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Create(&model.Setting{Key: "version", Value: version}).Error; err != nil {
				t.Fatal(err)
			}
			item := model.Client{Name: "backup-fixture", Config: json.RawMessage(`{}`)}
			if err := db.Create(&item).Error; err != nil {
				t.Fatal(err)
			}
			getBackup := GetDb
			if format == "zip" {
				getBackup = GetFullBackup
			}
			body, err := getBackup("")
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Delete(&item).Error; err != nil {
				t.Fatal(err)
			}
			if format == "zip" {
				if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x32}, 32), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := restoreDB(backupMemoryFile{bytes.NewReader(body)}); err != nil {
				t.Fatal(err)
			}
			var restored model.Client
			if err := db.First(&restored, item.Id).Error; err != nil || restored.Name != item.Name {
				t.Fatalf("restored client: %v", err)
			}
			if format == "zip" {
				actual, err := os.ReadFile(keyPath)
				if err != nil || !bytes.Equal(actual, key) {
					t.Fatal("restored key does not match the backup", err)
				}
			}
		})
	}
}
