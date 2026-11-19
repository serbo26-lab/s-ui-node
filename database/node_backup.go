package database

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/alireza0/s-ui/config"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

var backupImportMu sync.Mutex

const backupLimit = 256 << 20

type nodeBackupManifest struct {
	Version        int    `json:"version"`
	DatabaseSHA256 string `json:"database_sha256"`
	KeySHA256      string `json:"key_sha256,omitempty"`
}

func backupHash(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }

func readOptionalKey(path string) ([]byte, error) {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(body) != 32 {
		return nil, errors.New("invalid_node_backup_key")
	}
	return body, nil
}

// The list is private cipher state, not arbitrary fields supplied by an archive.
var nodeCipherColumns = map[string][]string{
	"node_installations": {"private_key", "server_certificate", "server_key"},
	"node_automations":   {"dns_token"}, "node_generated_materials": {"encrypted_value"},
	"node_dns_profiles": {"secret"}, "node_certificate_bindings": {"material", "account_key", "desired_request"},
	"node_certificate_versions": {"bundle"}, "node_jobs": {"plan"},
}

func validateNodeBackupKey(path string, key []byte) error {
	candidate, err := gorm.Open(sqlite.Open("file:"+filepath.ToSlash(path)+"?mode=ro"), &gorm.Config{Logger: gormlogger.Discard})
	if err != nil {
		return err
	}
	sqlDB, err := candidate.DB()
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	var aead cipher.AEAD
	if len(key) > 0 {
		if len(key) != 32 {
			return errors.New("invalid_node_backup_key")
		}
		block, e := aes.NewCipher(key)
		if e != nil {
			return e
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return err
		}
	}
	for table, columns := range nodeCipherColumns {
		if !candidate.Migrator().HasTable(table) {
			continue
		}
		for _, column := range columns {
			if !candidate.Migrator().HasColumn(table, column) {
				continue
			}
			rows, err := candidate.Raw(fmt.Sprintf(`SELECT "%s" FROM "%s" WHERE "%s" <> ''`, column, table, column)).Rows()
			if err != nil {
				return err
			}
			for rows.Next() {
				var sealed string
				if err = rows.Scan(&sealed); err != nil {
					rows.Close()
					return err
				}
				if aead == nil {
					rows.Close()
					return errors.New("node_backup_key_required")
				}
				body, e := base64.StdEncoding.DecodeString(sealed)
				if e != nil || len(body) < aead.NonceSize() {
					rows.Close()
					return errors.New("node_backup_key_mismatch")
				}
				if _, e = aead.Open(nil, body[:aead.NonceSize()], body[aead.NonceSize():], []byte("s-ui-node-provision-v1")); e != nil {
					rows.Close()
					return errors.New("node_backup_key_mismatch")
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func validateBackupBytes(body, key []byte) error {
	f, err := os.CreateTemp(config.GetDBFolderPath(), ".backup-key-check-*.db")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	defer removeSidecars(name)
	if _, err = f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = validateImport(name); err != nil {
		return err
	}
	return validateNodeBackupKey(name, key)
}

func GetFullBackup(exclude string) ([]byte, error) {
	backupImportMu.Lock()
	defer backupImportMu.Unlock()
	for _, name := range strings.Split(exclude, ",") {
		name = strings.TrimSpace(name)
		if name != "" && name != "stats" && name != "changes" {
			return nil, errors.New("incomplete_node_backup_exclusions")
		}
	}
	keyPath := filepath.Join(config.GetDBFolderPath(), "node-provision.key")
	key, err := readOptionalKey(keyPath)
	if err != nil {
		return nil, err
	}
	body, err := GetDb(exclude)
	if err != nil {
		return nil, err
	}
	after, err := readOptionalKey(keyPath)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(key, after) {
		return nil, errors.New("node_backup_key_changed")
	}
	if err = validateBackupBytes(body, key); err != nil {
		return nil, err
	}
	manifest := nodeBackupManifest{Version: 1, DatabaseSHA256: backupHash(body)}
	if len(key) > 0 {
		manifest.KeySHA256 = backupHash(key)
	}
	encoded, _ := json.Marshal(manifest)
	var output bytes.Buffer
	archive := zip.NewWriter(&output)
	files := map[string][]byte{"panel.db": body, "manifest.json": encoded}
	if len(key) > 0 {
		files["node-provision.key"] = key
	}
	for _, name := range []string{"manifest.json", "panel.db", "node-provision.key"} {
		data, exists := files[name]
		if !exists {
			continue
		}
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0600)
		file, e := archive.CreateHeader(h)
		if e != nil {
			return nil, e
		}
		if _, e = file.Write(data); e != nil {
			return nil, e
		}
	}
	if err = archive.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func readFullBackup(reader io.ReaderAt, size int64) ([]byte, []byte, error) {
	if size <= 0 || size > backupLimit {
		return nil, nil, errors.New("invalid_node_backup_archive")
	}
	archive, err := zip.NewReader(reader, size)
	if err != nil {
		return nil, nil, errors.New("invalid_node_backup_archive")
	}
	files := map[string][]byte{}
	var total uint64
	for _, file := range archive.File {
		if file.Name != "panel.db" && file.Name != "node-provision.key" && file.Name != "manifest.json" {
			return nil, nil, errors.New("invalid_node_backup_archive")
		}
		if _, exists := files[file.Name]; exists {
			return nil, nil, errors.New("invalid_node_backup_archive")
		}
		limit := uint64(backupLimit)
		if file.Name == "node-provision.key" {
			limit = 32
		}
		if file.Name == "manifest.json" {
			limit = 4096
		}
		total += file.UncompressedSize64
		if file.UncompressedSize64 > limit || total > backupLimit {
			return nil, nil, errors.New("invalid_node_backup_archive")
		}
		stream, e := file.Open()
		if e != nil {
			return nil, nil, e
		}
		body, e := io.ReadAll(io.LimitReader(stream, int64(limit)+1))
		stream.Close()
		if e != nil || uint64(len(body)) > limit {
			return nil, nil, errors.New("invalid_node_backup_archive")
		}
		files[file.Name] = body
	}
	var manifest nodeBackupManifest
	if json.Unmarshal(files["manifest.json"], &manifest) != nil || manifest.Version != 1 || manifest.DatabaseSHA256 != backupHash(files["panel.db"]) {
		return nil, nil, errors.New("invalid_node_backup_manifest")
	}
	key := files["node-provision.key"]
	if len(key) > 0 && (len(key) != 32 || manifest.KeySHA256 != backupHash(key)) {
		return nil, nil, errors.New("node_backup_key_mismatch")
	}
	if manifest.KeySHA256 != "" && len(key) == 0 {
		return nil, nil, errors.New("node_backup_key_required")
	}
	if err = validateBackupBytes(files["panel.db"], key); err != nil {
		return nil, nil, err
	}
	return files["panel.db"], key, nil
}

// A prepared pair is rolled back after a crash; a ready pair has both new
// files durably installed. Startup never opens a half-restored DB/key pair.
type backupPairJournal struct {
	Version  int    `json:"version"`
	Fallback string `json:"fallback"`
	OldKey   bool   `json:"old_key"`
	Ready    bool   `json:"ready"`
}

func pairJournalPath(dbPath string) string { return dbPath + ".restore-pair.json" }
func writePairJournal(dbPath string, j backupPairJournal) error {
	body, _ := json.Marshal(j)
	return backupWritePrivate(pairJournalPath(dbPath), body)
}
func backupWritePrivate(path string, body []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".restore-write-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(body)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	folder, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer folder.Close()
	return folder.Sync()
}

func recoverBackupPair(dbPath string) error {
	body, err := os.ReadFile(pairJournalPath(dbPath))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var journal backupPairJournal
	if json.Unmarshal(body, &journal) != nil || journal.Version != 1 || filepath.Base(journal.Fallback) != journal.Fallback || !strings.HasPrefix(journal.Fallback, filepath.Base(dbPath)+".backup-") {
		return errors.New("invalid_restore_pair_journal")
	}
	folder := filepath.Dir(dbPath)
	fallback := filepath.Join(folder, journal.Fallback)
	keyPath := filepath.Join(folder, "node-provision.key")
	if journal.Ready {
		key, err := readOptionalKey(keyPath)
		if err != nil {
			return err
		}
		if err = validateNodeBackupKey(dbPath, key); err != nil {
			return err
		}
	} else if _, err = os.Stat(fallback); err == nil {
		removeSidecars(dbPath)
		if err = os.Rename(fallback, dbPath); err != nil {
			return err
		}
		if journal.OldKey {
			key, err := os.ReadFile(fallback + ".key")
			if err != nil {
				return err
			}
			if err = backupWritePrivate(keyPath, key); err != nil {
				return err
			}
		} else if err = os.Remove(keyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Remove(pairJournalPath(dbPath))
}

type backupMemoryFile struct{ *bytes.Reader }

func (backupMemoryFile) Close() error { return nil }

func backupReadSource() (*gorm.DB, func(), error) {
	var files []struct {
		Name string
		File string
	}
	if err := db.Raw("PRAGMA database_list").Scan(&files).Error; err != nil {
		return nil, nil, err
	}
	for _, file := range files {
		if file.Name == "main" && file.File != "" {
			source, err := gorm.Open(sqlite.Open("file:"+filepath.ToSlash(file.File)+"?mode=ro&_busy_timeout=10000&_txlock=deferred"), &gorm.Config{Logger: gormlogger.Discard})
			if err != nil {
				return nil, nil, err
			}
			pool, err := source.DB()
			if err != nil {
				return nil, nil, err
			}
			return source, func() { pool.Close() }, nil
		}
	}
	return db, func() {}, nil
}

func copyBackupSequences(source, target *gorm.DB) error {
	if !source.Migrator().HasTable("sqlite_sequence") {
		return nil
	}
	var rows []struct {
		Name string
		Seq  int64
	}
	if err := source.Raw("SELECT name,seq FROM sqlite_sequence").Scan(&rows).Error; err != nil {
		return err
	}
	for _, row := range rows {
		if !target.Migrator().HasTable(row.Name) {
			continue
		}
		result := target.Exec("UPDATE sqlite_sequence SET seq=MAX(seq,?) WHERE name=?", row.Seq, row.Name)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			if err := target.Exec("INSERT INTO sqlite_sequence(name,seq) VALUES(?,?)", row.Name, row.Seq).Error; err != nil {
				return err
			}
		}
	}
	return nil
}
