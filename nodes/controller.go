package nodes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/nodeagent"
	"gorm.io/gorm"
)

var nodeLocks sync.Map

func snapshotFingerprint(snapshot Snapshot) (string, error) {
	body, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func Start(parent context.Context, traffic TrafficConfig) context.CancelFunc {
	ctx, cancel := context.WithCancel(parent)
	ctx = context.WithValue(ctx, trafficConfigKey{}, traffic)
	initializeProvisionJobs(ctx)
	go accessLoop(ctx)
	go resourceLoop(ctx)
	go upgradeAgentsLoop(ctx)
	go controlRenewalLoop(ctx)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			ReconcileAll(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return cancel
}

func ReconcileAll(ctx context.Context) {
	var list []model.Node
	if database.GetDB().Order("id").Find(&list).Error != nil {
		return
	}
	limit := make(chan struct{}, 4)
	var wait sync.WaitGroup
	for _, node := range list {
		if jobRunning(node.Id) {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		limit <- struct{}{}
		wait.Add(1)
		go func(id uint) { defer wait.Done(); defer func() { <-limit }(); _ = Reconcile(ctx, id) }(node.Id)
	}
	wait.Wait()
}

func Reconcile(ctx context.Context, id uint) (failure error) {
	lock, _ := nodeLocks.LoadOrStore(id, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	db := database.GetDB()
	var node model.Node
	if err := db.First(&node, id).Error; err != nil {
		return err
	}
	if node.AgentProtocol == 2 || discoverV2(ctx, &node) {
		return reconcileStructureV2(ctx, node)
	}
	stage := "compile_failed"
	defer func() {
		if failure != nil && ctx.Err() == nil {
			db.Model(&model.Node{}).Where("id = ?", id).Update("last_error", stage)
		}
	}()
	desired, err := prepareDesired(db, node, nodeagent.Status{})
	if err != nil {
		return err
	}
	stage = "control_config_invalid"
	if err := validateControl(node); err != nil {
		return err
	}
	cert, err := tls.X509KeyPair([]byte(node.ControlCertificate), []byte(node.ControlKey))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(node.ControlCA))
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert}}}
	var installation model.NodeInstallation
	if database.GetDB().First(&installation, whereNodeID, node.Id).Error == nil && installation.PrivateKey != "" {
		if !jobRunning(node.Id) && len(installation.PreviousTarget) > 0 {
			retryPreviousRetirement(ctx, installation)
		}
		stage = "ssh_unreachable"
		sshClient, _, err := managedTransport(ctx, node.Id)
		if err != nil {
			return err
		}
		defer sshClient.Close()
		transport.DialContext = sshClient.DialContext
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get, err := http.NewRequestWithContext(ctx, http.MethodGet, node.Address+"/v1/status", nil)
	if err != nil {
		return err
	}
	stage = "control_unreachable"
	response, err := client.Do(get)
	if err != nil {
		return err
	}
	stage = "status_invalid"
	var status nodeagent.Status
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&status)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 {
		return errors.New("cannot read node status")
	}
	if status.NodeID != uint64(node.Id) || status.Protocol != nodeagent.ProtocolVersion {
		return errors.New("node identity or protocol does not match registration")
	}
	if err := db.Model(&model.Node{}).Where("id = ? AND address = ?", id, node.Address).Update("tls_status", certificateReport(status)).Error; err != nil {
		return err
	}
	if err := db.Model(&model.Node{}).Where("id = ? AND address = ?", id, node.Address).Update("last_seen", time.Now().Unix()).Error; err != nil {
		return err
	}
	stage = "compile_failed"
	if err := confirmLegacyNodeFirewall(ctx, db, node, status); err != nil {
		stage = errNodeFirewall.Error()
		return err
	}
	desired, err = prepareDesired(db, node, status)
	if err != nil {
		return err
	}
	if status.Revision != desired.Deployment.Revision || status.Digest != desired.Deployment.Digest() || !status.Running {
		// A confirmed application failure must not restart the last-good core
		// every poll. Changed intent or an explicit retry allocates a new revision.
		if node.RejectedRevision == desired.Deployment.Revision && status.Running {
			stage = "deployment_rejected"
			return errors.New("this revision was rejected; change settings or explicitly retry")
		}
		stage = errNodeFirewall.Error()
		if err := ensureNodeFirewall(ctx, db, node, desired, false); err != nil {
			return err
		}
		status, err = sendLegacyDeployment(ctx, db, node, desired, client, &stage, status)
		if err != nil {
			return err
		}
	}
	stage = errNodeFirewall.Error()
	if err := ensureNodeFirewall(ctx, db, node, desired, true); err != nil {
		return err
	}
	stage = "ack_save_failed"
	body, _ := json.Marshal(desired)
	return db.Model(&model.Node{}).Where("id = ? AND desired_revision = ?", id, desired.Deployment.Revision).
		Updates(map[string]interface{}{"applied_revision": desired.Deployment.Revision, "applied_snapshot": json.RawMessage(body), "tls_status": certificateReport(status), "rejected_revision": 0, "last_error": "", "last_seen": time.Now().Unix()}).Error
}

// Compile and persist intent before network I/O, including during outages.
func prepareDesired(db *gorm.DB, node model.Node, status nodeagent.Status) (Snapshot, error) {
	id := node.Id
	var desired Snapshot
	err := db.Transaction(func(tx *gorm.DB) error {
		var current model.Node
		if err := tx.First(&current, id).Error; err != nil {
			return err
		}
		if current.Address != node.Address || current.ControlCertificate != node.ControlCertificate || current.ControlKey != node.ControlKey || current.ControlCA != node.ControlCA {
			return errors.New("node connection settings changed; retry")
		}
		fresh, err := Compile(tx, current)
		if err != nil {
			return err
		}
		fingerprint, err := snapshotFingerprint(fresh)
		if err != nil {
			return err
		}
		var prior Snapshot
		priorErr := json.Unmarshal(current.DesiredSnapshot, &prior)
		conflict := status.Revision == current.DesiredRevision && status.Digest != prior.Deployment.Digest()
		if fingerprint != current.DesiredFingerprint || current.DesiredRevision == 0 || status.Revision > current.DesiredRevision || priorErr != nil || conflict {
			revision := current.DesiredRevision
			if status.Revision > revision {
				revision = status.Revision
			}
			revision++
			fresh.Deployment.Revision = revision
			if err := fresh.Deployment.Validate(); err != nil {
				return err
			}
			body, err := json.Marshal(fresh)
			if err != nil {
				return err
			}
			if err := tx.Model(&model.Node{}).Where("id = ?", id).Updates(map[string]interface{}{"desired_revision": revision, "desired_fingerprint": fingerprint, "desired_snapshot": json.RawMessage(body)}).Error; err != nil {
				return err
			}
			desired = fresh
		} else {
			if err := json.Unmarshal(current.DesiredSnapshot, &desired); err != nil {
				return err
			}
		}
		return nil
	})
	return desired, err
}

func sendLegacyDeployment(ctx context.Context, db *gorm.DB, node model.Node, desired Snapshot, client *http.Client, stage *string, status nodeagent.Status) (nodeagent.Status, error) {
	body, _ := json.Marshal(desired.Deployment)
	put, err := http.NewRequestWithContext(ctx, http.MethodPut, node.Address+"/v1/deployment", bytes.NewReader(body))
	if err != nil {
		return status, err
	}
	put.Header.Set("Content-Type", "application/json")
	*stage = "deployment_unreachable"
	response, err := client.Do(put)
	if err != nil {
		return status, err
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&status)
	response.Body.Close()
	*stage = "deployment_rejected"
	if response.StatusCode != 200 {
		if response.StatusCode == http.StatusUnprocessableEntity {
			if saveErr := db.Model(&model.Node{}).Where("id = ? AND desired_revision = ?", node.Id, desired.Deployment.Revision).Update("rejected_revision", desired.Deployment.Revision).Error; saveErr != nil {
				return status, saveErr
			}
			if cleanupErr := confirmLegacyNodeFirewall(ctx, db, node, status); cleanupErr != nil {
				*stage = errNodeFirewall.Error()
				return status, cleanupErr
			}
		}
		return status, fmt.Errorf("node rejected deployment: HTTP %d", response.StatusCode)
	}
	*stage = "ack_mismatch"
	if err != nil || status.Revision != desired.Deployment.Revision || status.Digest != desired.Deployment.Digest() || !status.Running {
		return status, errors.New("node did not confirm the expected revision")
	}
	if status.NodeID != uint64(node.Id) || status.Protocol != nodeagent.ProtocolVersion {
		return status, errors.New("node acknowledgement identity does not match")
	}
	return status, nil
}
