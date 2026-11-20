package nodes

import (
	"encoding/json"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/nodeagent"
	"strings"
	"testing"
	"time"
)

func TestProviderEndpointNeedsCertificateReportForConfirmedRevision(t *testing.T) {
	node := model.Node{Id: 1}
	snapshot := Snapshot{Deployment: nodeagent.Deployment{Revision: 7}}
	inbound := model.NodeInbound{Id: 2, Options: json.RawMessage(`{"tls":{"enabled":true,"certificate_provider":"own"}}`)}
	if certificatePublished(node, snapshot, inbound) {
		t.Fatal("published before certificate available")
	}
	status := nodeagent.Status{Revision: 7, Certificates: []nodeagent.CertificateStatus{{Inbound: "node-1-inbound-2", State: "ready", NotAfter: time.Now().Add(time.Hour).Unix()}}}
	node.TLSStatus = certificateReport(status)
	if !certificatePublished(node, snapshot, inbound) {
		t.Fatal("ready certificate hidden")
	}
	status.Revision = 6
	node.TLSStatus = certificateReport(status)
	if certificatePublished(node, snapshot, inbound) {
		t.Fatal("stale report published")
	}
	status.Revision = 7
	status.Certificates[0].NotAfter = time.Now().Add(-time.Second).Unix()
	node.TLSStatus = certificateReport(status)
	if certificatePublished(node, snapshot, inbound) {
		t.Fatal("expired certificate published")
	}
}

func TestReferencedProviderCannotBeRemovedFromNodeConfig(t *testing.T) {
	db, node, _ := fixture(t)
	server, identity := controlServer(t, nil)
	defer server.Close()
	node.Address = server.URL
	node.ControlCA = identity.CA
	node.ControlCertificate = identity.Certificate
	node.ControlKey = identity.Key
	node.Config = json.RawMessage(`{"certificate_providers":[{"type":"acme","tag":"own","domain":["vpn.example"]}]}`)
	if err := db.Save(&node).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.NodeInbound{}).Where("id = 1").Update("options", json.RawMessage(`{"listen_port":14443,"tls":{"enabled":true,"certificate_provider":"own","server_name":"vpn.example"}}`)).Error; err != nil {
		t.Fatal(err)
	}
	if err := Save("nodes", "edit", json.RawMessage(`{"id":1,"config":{}}`), "test"); err == nil || !strings.Contains(err.Error(), "unknown node certificate provider") {
		t.Fatal("expected reference validation", err)
	}
	var saved model.Node
	if err := db.First(&saved, 1).Error; err != nil {
		t.Fatal(err)
	}
	if string(saved.Config) != string(node.Config) {
		t.Fatal("failed edit changed stored provider")
	}
}
