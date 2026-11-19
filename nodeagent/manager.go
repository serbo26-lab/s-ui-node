package nodeagent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrConflict = errors.New("deployment revision or node identity conflict")

type Runtime interface {
	Validate([]byte) error
	Apply([]byte) error
	Close() error
	Running() bool
}

type Status struct {
	Protocol     int                 `json:"protocol"`
	NodeID       uint64              `json:"node_id"`
	Revision     uint64              `json:"revision"`
	Digest       string              `json:"digest,omitempty"`
	Running      bool                `json:"running"`
	Error        string              `json:"error,omitempty"`
	Certificates []CertificateStatus `json:"certificates,omitempty"`
}

type Manager struct {
	mu        sync.Mutex
	nodeID    uint64
	store     Store
	runtime   Runtime
	current   *Deployment
	effective []byte
	lastError string
	clock     func() time.Time
}

func NewManager(nodeID uint64, store Store, runtime Runtime) *Manager {
	return &Manager{nodeID: nodeID, store: store, runtime: runtime, clock: time.Now}
}

func (m *Manager) Restore() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.store.Load()
	if err != nil || d == nil {
		return err
	}
	if err := d.Validate(); err != nil {
		return err
	}
	if d.NodeID != m.nodeID {
		return ErrConflict
	}
	effective, err := d.Effective(m.clock().Unix())
	if err == nil {
		err = m.runtime.Validate(effective)
	}
	if err == nil {
		err = m.runtime.Apply(effective)
	}
	if err != nil {
		return fmt.Errorf("restore saved deployment: %w", err)
	}
	m.current, m.effective = d, effective
	return nil
}

func (m *Manager) Apply(d Deployment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := d.Validate(); err != nil {
		return err
	}
	if d.NodeID != m.nodeID {
		return ErrConflict
	}
	if m.current != nil {
		if d.Revision < m.current.Revision {
			return ErrConflict
		}
		if d.Revision == m.current.Revision {
			if d.Digest() != m.current.Digest() {
				return ErrConflict
			}
			if !m.runtime.Running() {
				effective, err := d.Effective(m.clock().Unix())
				if err == nil {
					err = m.runtime.Validate(effective)
				}
				if err == nil {
					err = m.runtime.Apply(effective)
				}
				if err != nil {
					m.recordFailure("recovery_failed", err)
					return err
				}
				m.effective, m.lastError = effective, ""
			}
			return nil
		}
	}
	// Detach from caller-owned slices before retaining any state.
	b, _ := json.Marshal(d)
	var candidate Deployment
	if err := json.Unmarshal(b, &candidate); err != nil {
		return err
	}
	effective, err := candidate.Effective(m.clock().Unix())
	if err == nil {
		err = m.runtime.Validate(effective)
	}
	if err != nil {
		m.recordFailure("validation_failed", err)
		return err
	}
	if err = m.runtime.Apply(effective); err != nil {
		m.recordFailure("apply_failed", err)
		return err
	}
	if err = m.store.Save(candidate); err != nil {
		var rollback error
		if m.current != nil {
			rollback = m.runtime.Apply(m.effective)
		} else {
			rollback = m.runtime.Close()
		}
		m.recordFailure("save_failed", err)
		return errors.Join(err, rollback)
	}
	m.current, m.effective, m.lastError = &candidate, effective, ""
	return nil
}

func (m *Manager) recordFailure(stage string, err error) {
	m.lastError = stage
	if recorder, ok := m.store.(interface{ RecordFailure(string, error) }); ok {
		recorder.RecordFailure(stage, err)
	}
}

// Refresh only enforces known expiries. No heartbeat timer stops the core.
func (m *Manager) Refresh() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		return nil
	}
	effective, err := m.current.Effective(m.clock().Unix())
	if err != nil || bytes.Equal(effective, m.effective) {
		return err
	}
	if err := m.runtime.Apply(effective); err != nil {
		m.lastError = "expiry_apply_failed"
		return err
	}
	m.effective, m.lastError = effective, ""
	return nil
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Status{Protocol: ProtocolVersion, NodeID: m.nodeID, Running: m.runtime.Running(), Error: m.lastError}
	if reporter, ok := m.runtime.(interface{ Certificates() []CertificateStatus }); ok {
		s.Certificates = reporter.Certificates()
	}
	if m.current != nil {
		s.Revision, s.Digest = m.current.Revision, m.current.Digest()
	}
	return s
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runtime.Close()
}
