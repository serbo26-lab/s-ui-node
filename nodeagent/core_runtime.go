package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/alireza0/s-ui/core"
	"github.com/alireza0/s-ui/nodecert"
	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/option"
)

// CoreRuntime reuses S-UI's core, never the panel's global ConfigService/corePtr.
type CoreRuntime struct {
	mu                  sync.Mutex
	core                *core.Core
	config              []byte
	stateDirectory      string
	cancel              context.CancelFunc
	cancelMu            sync.Mutex
	certificateResolver func(string) (nodecert.Metadata, error)
	traffic             TrafficSample
}

func (r *CoreRuntime) SetCertificateResolver(resolve func(string) (nodecert.Metadata, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.certificateResolver = resolve
}

func NewCoreRuntime() *CoreRuntime { r := &CoreRuntime{}; r.freshCore(); return r }

func (r *CoreRuntime) freshCore() {
	ctx, cancel := context.WithCancel(context.Background())
	r.core = core.NewCoreWithContext(ctx)
	r.cancelMu.Lock()
	r.cancel = cancel
	r.cancelMu.Unlock()
}

// Interrupt can cancel network-bound startup without waiting for the apply lock.
func (r *CoreRuntime) Interrupt() {
	r.cancelMu.Lock()
	cancel := r.cancel
	r.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (r *CoreRuntime) stopCore() error {
	r.collectTraffic()
	r.Interrupt()
	err := r.core.Stop()
	r.freshCore()
	return err
}

func NewCoreRuntimeWithState(directory string) *CoreRuntime {
	r := NewCoreRuntime()
	r.stateDirectory, _ = filepath.Abs(directory)
	return r
}

func (r *CoreRuntime) Validate(config []byte) error {
	var err error
	config, err = r.prepareCertificates(config, false)
	if err != nil {
		return err
	}
	var options option.Options
	if err := options.UnmarshalJSONContext(r.core.GetCtx(), config); err != nil {
		return err
	}
	var raw struct {
		Inbounds []struct {
			Type  string `json:"type"`
			Users []struct {
				UUID     string `json:"uuid"`
				Password string `json:"password"`
			} `json:"users"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &raw); err != nil {
		return err
	}
	for _, inbound := range raw.Inbounds {
		for _, user := range inbound.Users {
			if NeedsUUID(inbound.Type) {
				if _, err := uuid.FromString(user.UUID); err != nil {
					return errors.New("invalid user UUID")
				}
			}
			if NeedsPassword(inbound.Type) && user.Password == "" {
				return errors.New("empty user password")
			}
		}
	}
	return nil
}

func (r *CoreRuntime) Apply(config []byte) error {
	return r.apply(config, true)
}

// ApplySafe never restores an older user list. The v2 manager owns recovery
// and rebuilds the last-good structure with the latest durable access intent.
func (r *CoreRuntime) ApplySafe(config []byte) error { return r.apply(config, false) }

func (r *CoreRuntime) apply(config []byte, rollback bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	prepared, err := r.prepareCertificates(config, true)
	if err != nil {
		return err
	}
	if err := r.Validate(config); err != nil {
		return err
	}
	config = prepared
	previous := append([]byte(nil), r.config...)
	if r.core.IsRunning() && r.core.GetCtx().Err() == nil && sameExceptUsers(previous, config) {
		if err := r.updateUsers(config); err == nil {
			r.config = append([]byte(nil), config...)
			return nil
		} else {
			// A multi-inbound update can fail after one success; rebuild the
			// previous full config rather than leaving a partially applied ACL.
			_ = r.stopCore()
			if !rollback {
				r.config = nil
				return err
			}
			return errors.Join(err, r.core.Start(previous))
		}
	}
	if err := r.stopCore(); err != nil {
		return err
	}
	if err := r.core.Start(config); err != nil {
		_ = r.stopCore()
		if rollback && len(previous) != 0 {
			return errors.Join(err, r.core.Start(previous))
		}
		return err
	}
	r.config = append([]byte(nil), config...)
	return nil
}

func (r *CoreRuntime) updateUsers(config []byte) error {
	previous, err := userFingerprints(r.config)
	if err != nil {
		return err
	}
	current, err := userFingerprints(config)
	if err != nil {
		return err
	}
	var data struct {
		Inbounds []json.RawMessage `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &data); err != nil {
		return err
	}
	for _, inbound := range data.Inbounds {
		var meta struct {
			Tag   string `json:"tag"`
			Users []struct {
				Name string `json:"name"`
			} `json:"users"`
		}
		if err := json.Unmarshal(inbound, &meta); err != nil {
			return err
		}
		updated, err := r.core.UpdateInboundUsers(inbound)
		if err != nil {
			return err
		}
		if !updated {
			return fmt.Errorf("inbound %q does not support user updates", meta.Tag)
		}
		keep := make(map[string]struct{}, len(meta.Users))
		for _, user := range meta.Users {
			// Reusing a name with a new UUID/password must also terminate
			// sessions authenticated with that name's previous credentials.
			if previous[meta.Tag][user.Name] == current[meta.Tag][user.Name] {
				keep[user.Name] = struct{}{}
			}
		}
		r.core.CloseInboundUserSessions(meta.Tag, keep)
		if box := r.core.GetInstance(); box != nil {
			box.SessionTracker().CloseByInboundUsers(meta.Tag, keep)
		}
	}
	return nil
}

func userFingerprints(config []byte) (map[string]map[string]string, error) {
	var data struct {
		Inbounds []struct {
			Tag   string                   `json:"tag"`
			Users []map[string]interface{} `json:"users"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &data); err != nil {
		return nil, err
	}
	result := map[string]map[string]string{}
	for _, inbound := range data.Inbounds {
		result[inbound.Tag] = map[string]string{}
		for _, user := range inbound.Users {
			name, _ := user["name"].(string)
			b, err := json.Marshal(user)
			if err != nil {
				return nil, err
			}
			result[inbound.Tag][name] = string(b)
		}
	}
	return result, nil
}

func (r *CoreRuntime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.config = nil
	r.collectTraffic()
	r.Interrupt()
	return r.core.Stop()
}

func (r *CoreRuntime) Running() bool { return r.core.IsRunning() && r.core.GetCtx().Err() == nil }

func sameExceptUsers(a, b []byte) bool {
	strip := func(data []byte) []byte {
		var config map[string]json.RawMessage
		if json.Unmarshal(data, &config) != nil {
			return nil
		}
		var inbounds []map[string]json.RawMessage
		if json.Unmarshal(config["inbounds"], &inbounds) != nil {
			return nil
		}
		for _, inbound := range inbounds {
			delete(inbound, "users")
		}
		config["inbounds"], _ = json.Marshal(inbounds)
		result, _ := json.Marshal(config)
		return result
	}
	x, y := strip(a), strip(b)
	return x != nil && y != nil && bytes.Equal(x, y)
}
