package nodes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/logger"
	"github.com/alireza0/s-ui/nodeagent"
	"gorm.io/gorm"
)

var errAgentV1 = errors.New("agent_v1")
var errV2Rejected = errors.New("v2_state_rejected")
var errAgentProtocolsPending = errors.New("node_agent_protocols_pending")

// A managed trial binary cannot introduce ACL fields its rollback binary would
// reject. Its capabilities are committed only after the remote trial succeeds.
func extendedInboundsAvailable(tx *gorm.DB, node model.Node, status nodeagent.StatusV2) bool {
	return inboundCapability(tx, node.Id, status.ExtendedInbounds, node.AgentExtendedInbounds)
}

func proxyInboundsAvailable(tx *gorm.DB, node model.Node, status nodeagent.StatusV2) bool {
	return inboundCapability(tx, node.Id, status.ProxyInbounds, node.AgentProxyInbounds)
}

func inboundCapability(tx *gorm.DB, id uint, advertised, confirmed bool) bool {
	if !advertised {
		return false
	}
	if confirmed {
		return true
	}
	var managed int64
	err := tx.Model(&model.NodeInstallation{}).Where("node_id = ? AND owner_id <> ''", id).Count(&managed).Error
	return err == nil && managed == 0
}

func controlClient(ctx context.Context, node model.Node) (*http.Client, func(), error) {
	if err := validateManagementControl(node); err != nil {
		return nil, nil, err
	}
	cert, err := tls.X509KeyPair([]byte(node.ControlCertificate), []byte(node.ControlKey))
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(node.ControlCA))
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert}}}
	closeTransport := func() { transport.CloseIdleConnections() }
	var installation model.NodeInstallation
	if database.GetDB().First(&installation, "node_id = ?", node.Id).Error == nil && installation.PrivateKey != "" {
		sshClient, _, err := managedTransport(ctx, node.Id)
		if err != nil {
			return nil, nil, err
		}
		transport.DialContext = sshClient.DialContext
		closeTransport = func() { transport.CloseIdleConnections(); sshClient.Close() }
	}
	return &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, closeTransport, nil
}

func recordV2Health(node model.Node, status nodeagent.StatusV2) error {
	result := database.GetDB().Model(&model.Node{}).Where("id = ? AND address = ? AND management_generation = ? AND (control_epoch = ? OR control_epoch = '')", node.Id, node.Address, node.ManagementGeneration, status.Epoch).Updates(map[string]interface{}{"agent_running": status.Running, "agent_observed_at": time.Now().Unix(), "last_seen": time.Now().Unix(), "sing_box_version": status.SingBoxVersion, "agent_digest": status.AgentDigest})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return errors.New("management_target_changed")
	}
	return nil
}

func getStatusV2(ctx context.Context, client *http.Client, node model.Node) (nodeagent.StatusV2, error) {
	var status nodeagent.StatusV2
	observed := time.Now()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, node.Address+"/v2/status", nil)
	if err != nil {
		return status, err
	}
	response, err := client.Do(request)
	if err != nil {
		return status, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return status, errAgentV1
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&status) != nil {
		return status, errors.New("invalid_v2_status")
	}
	if status.Protocol != nodeagent.ProtocolV2 || status.NodeID != uint64(node.Id) || status.Epoch == "" {
		return status, errors.New("v2_identity_mismatch")
	}
	if node.ControlEpoch != "" && node.ControlEpoch != status.Epoch {
		return status, errors.New("agent_epoch_changed_recovery_required")
	}
	if err := recordV2Health(node, status); err != nil {
		return status, err
	}
	if traffic, ok := ctx.Value(trafficConfigKey{}).(TrafficConfig); ok && traffic.Enabled && status.Traffic != nil {
		if err := recordNodeTraffic(database.GetDB(), node, status.Traffic, observed, traffic.BucketSeconds); err != nil {
			logger.Warning("could not record node traffic sample")
		}
	}
	return status, nil
}

func pinV2(node *model.Node, status nodeagent.StatusV2) error {
	err := database.GetDB().Transaction(func(tx *gorm.DB) error {
		var current model.Node
		if err := tx.First(&current, node.Id).Error; err != nil {
			return err
		}
		if current.ManagementGeneration != node.ManagementGeneration || current.Address != node.Address || current.ControlCertificate != node.ControlCertificate || current.ControlCA != node.ControlCA || current.ControlKey != node.ControlKey {
			return errors.New("control_settings_changed")
		}
		if current.ControlEpoch != "" && current.ControlEpoch != status.Epoch {
			return errors.New("agent_epoch_changed_recovery_required")
		}
		return tx.Model(&current).Updates(map[string]interface{}{"agent_protocol": nodeagent.ProtocolV2, "control_epoch": status.Epoch, "last_seen": time.Now().Unix()}).Error
	})
	if err == nil {
		node.AgentProtocol = nodeagent.ProtocolV2
		node.ControlEpoch = status.Epoch
	}
	return err
}

func discoverV2(ctx context.Context, node *model.Node) bool {
	client, closeClient, err := controlClient(ctx, *node)
	if err != nil {
		return false
	}
	defer closeClient()
	status, err := getStatusV2(ctx, client, *node)
	return err == nil && pinV2(node, status) == nil
}

func putV2(ctx context.Context, client *http.Client, node model.Node, path string, value interface{}) (nodeagent.StatusV2, error) {
	var status nodeagent.StatusV2
	body, err := json.Marshal(value)
	if err != nil {
		return status, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, node.Address+path, bytes.NewReader(body))
	if err != nil {
		return status, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return status, err
	}
	defer response.Body.Close()
	if response.StatusCode == 422 {
		return status, errV2Rejected
	}
	if response.StatusCode != 200 {
		return status, errors.New("v2_state_not_accepted")
	}
	if json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&status) != nil || status.Protocol != 2 || status.NodeID != uint64(node.Id) || status.Epoch != node.ControlEpoch {
		return status, errors.New("v2_ack_identity_mismatch")
	}
	if err := recordV2Health(node, status); err != nil {
		return status, err
	}
	return status, nil
}
