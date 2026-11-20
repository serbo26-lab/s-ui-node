package nodeagent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Store interface {
	Load() (*Deployment, error)
	Save(Deployment) error
}

type FileStore struct{ Directory string }

// Failure details can include parser input. Keep them in the private state
// directory, never in the public HTTP status response.
func (s FileStore) RecordFailure(stage string, failure error) {
	if os.MkdirAll(s.Directory, 0o700) != nil {
		return
	}
	b, err := json.Marshal(map[string]string{"utc": time.Now().UTC().Format(time.RFC3339), "stage": stage, "error": failure.Error()})
	if err == nil {
		_ = os.WriteFile(filepath.Join(s.Directory, "last-error.json"), b, 0o600)
	}
}

type diskRecord struct {
	Version    int        `json:"version"`
	Deployment Deployment `json:"deployment"`
	Digest     string     `json:"digest"`
}

func (s FileStore) Load() (*Deployment, error) {
	b, err := os.ReadFile(filepath.Join(s.Directory, "last-good.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record diskRecord
	if err := json.Unmarshal(b, &record); err != nil {
		return nil, err
	}
	if record.Version != ProtocolVersion || record.Digest != record.Deployment.Digest() {
		return nil, errors.New("invalid saved deployment version or digest")
	}
	if err := record.Deployment.Validate(); err != nil {
		return nil, err
	}
	return &record.Deployment, nil
}

func (s FileStore) Save(d Deployment) error {
	if err := os.MkdirAll(s.Directory, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Directory, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(diskRecord{ProtocolVersion, d, d.Digest()})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.Directory, ".deployment-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("write deployment: %w", err)
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, filepath.Join(s.Directory, "last-good.json"))
}
