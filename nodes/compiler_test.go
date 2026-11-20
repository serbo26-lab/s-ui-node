package nodes

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/nodeagent"
	"gorm.io/gorm"
)

func fixture(t *testing.T) (*gorm.DB, model.Node, model.Client) {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "nodes.db")); err != nil {
		t.Fatal(err)
	}
	db := database.GetDB()
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	node := model.Node{Id: 1, Name: "one", Enable: true, LinkAddress: "first.example"}
	client := model.Client{Id: 1, Name: "one", Enable: true, Inbounds: json.RawMessage(`[1]`), Links: json.RawMessage(`[]`), Config: json.RawMessage(`{"vless":{"name":"one","uuid":"11111111-1111-4111-8111-111111111111","flow":"xtls-rprx-vision"}}`)}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	options, _ := json.Marshal(map[string]interface{}{"listen": "::", "listen_port": 14443, "tls": map[string]interface{}{"enabled": true, "server_name": "www.example.com", "reality": map[string]interface{}{"enabled": true, "private_key": base64.RawURLEncoding.EncodeToString(private.Bytes()), "short_id": []string{"01234567"}, "handshake": map[string]interface{}{"server": "www.example.com", "server_port": 443}}}})
	for _, value := range []interface{}{&node, &client, &model.Inbound{Id: 1, Tag: "same", Type: "vless", Enable: true, Options: json.RawMessage(`{}`)}, &model.NodeInbound{Id: 1, NodeId: 1, Tag: "same", Type: "vless", Enable: true, Options: options}, &model.ClientNodeInbound{ClientId: 1, NodeInboundId: 1}} {
		if err := db.Create(value).Error; err != nil {
			t.Fatal(err)
		}
	}
	return db, node, client
}

func confirm(t *testing.T, db *gorm.DB, node model.Node) Snapshot {
	t.Helper()
	s, err := Compile(db, node)
	if err != nil {
		t.Fatal(err)
	}
	s.Deployment.Revision = 5
	if err := s.Deployment.Validate(); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(s)
	if err := db.Model(&model.Node{}).Where("id = ?", node.Id).Updates(map[string]interface{}{"applied_revision": 5, "applied_snapshot": json.RawMessage(body)}).Error; err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPublicationUsesConfirmedSnapshotAndSeparateIDs(t *testing.T) {
	db, node, client := fixture(t)
	endpoints, err := ClientInbounds(db, client)
	if err != nil || len(endpoints) != 0 {
		t.Fatal("unconfirmed configuration was published", err)
	}
	s := confirm(t, db, node)
	if !strings.Contains(string(s.Deployment.Config), `"tag":"node-1-inbound-1"`) || !strings.Contains(string(s.Deployment.Config), `"name":"client/1"`) {
		t.Fatal("unstable node/user identity")
	}
	endpoints, err = ClientInbounds(db, client)
	if err != nil || len(endpoints) != 1 {
		t.Fatal("confirmed endpoint missing", err)
	}
	if !strings.Contains(string(endpoints[0].Addrs), "first.example") {
		t.Fatal("incorrect published node address")
	}
	public, _ := json.Marshal(endpoints[0])
	public = append(public, endpoints[0].OutJson...)
	var options map[string]interface{}
	_ = json.Unmarshal(s.Inbounds[0].Options, &options)
	key := options["tls"].(map[string]interface{})["reality"].(map[string]interface{})["private_key"].(string)
	if strings.Contains(string(public), key) || strings.Contains(string(public), "private_key") || strings.Contains(string(public), "handshake") {
		t.Fatal("server-only material leaked into endpoint")
	}
	if !strings.Contains(string(public), "public_key") {
		t.Fatal("REALITY public key was not derived")
	}
	if err := db.Model(&model.Node{}).Where("id = 1").Update("link_address", "pending.example").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.NodeInbound{}).Where("id = 1").Update("options", json.RawMessage(`{"listen_port":29999}`)).Error; err != nil {
		t.Fatal(err)
	}
	endpoints, err = ClientInbounds(db, client)
	if err != nil || len(endpoints) != 1 || !strings.Contains(string(endpoints[0].Addrs), "first.example") {
		t.Fatal("pending edit replaced working publication", err)
	}
	client.Config = json.RawMessage(`{"vless":{"uuid":"22222222-2222-4222-8222-222222222222"}}`)
	endpoints, err = ClientInbounds(db, client)
	if err != nil || len(endpoints) != 0 {
		t.Fatal("unconfirmed changed user credentials were published", err)
	}
	var count int64
	db.Model(&model.Inbound{}).Count(&count)
	if count != 1 {
		t.Fatal("remote publication modified local inbounds")
	}
}

func TestCurrentRevocationHidesPreviouslyAppliedEndpoint(t *testing.T) {
	db, node, client := fixture(t)
	confirm(t, db, node)
	client.Enable = false
	endpoints, err := ClientInbounds(db, client)
	if err != nil || len(endpoints) != 0 {
		t.Fatal("disabled client retained endpoint", err)
	}
	client.Enable = true
	client.Expiry = time.Now().Unix() - 1
	endpoints, err = ClientInbounds(db, client)
	if err != nil || len(endpoints) != 0 {
		t.Fatal("expired client retained endpoint", err)
	}
	client.Expiry = 0
	if err := db.Where("client_id = 1").Delete(&model.ClientNodeInbound{}).Error; err != nil {
		t.Fatal(err)
	}
	endpoints, err = ClientInbounds(db, client)
	if err != nil || len(endpoints) != 0 {
		t.Fatal("removed assignment retained endpoint", err)
	}
}

func TestAccessEpochRequiresNewConfirmationWithoutChangingCustomerKeys(t *testing.T) {
	db, node, client := fixture(t)
	confirm(t, db, node)
	client.NodeGeneration = 2
	endpoints, err := ClientInbounds(db, client)
	if err != nil || len(endpoints) != 0 {
		t.Fatal("prior access epoch was treated as confirmed", err)
	}
	if err := db.Save(&client).Error; err != nil {
		t.Fatal(err)
	}
	s, err := Compile(db, node)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Deployment.Users) != 1 || s.Deployment.Users[0].Name != "client/1/g2" {
		t.Fatal("new node session identity missing")
	}
	if !strings.Contains(string(s.Deployment.Config), "11111111-1111-4111-8111-111111111111") {
		t.Fatal("access epoch rotated customer UUID")
	}
}

func TestNodeClientTLSRejectsServerKeysAndNodeLocalPaths(t *testing.T) {
	_, _, _ = fixture(t)
	for _, raw := range []string{`{"private_key":"secret"}`, `{"reality":{"private_key":"secret"}}`, `{"certificate_path":"/node/cert.pem"}`, `{"client_key_path":"/node/client-key.pem"}`, `{"ech":{"config_path":"/node/ech.txt"}}`} {
		inbound := model.NodeInbound{Options: json.RawMessage(`{"tls":{"enabled":true}}`), ClientTLS: json.RawMessage(raw)}
		if _, _, err := clientTLS(inbound); err == nil {
			t.Fatal("accepted key/path in public node TLS", raw)
		}
	}
}

type testRuntime struct {
	running  bool
	reject   bool
	applies  int
	attempts int
}

func (r *testRuntime) Validate([]byte) error { return nil }
func (r *testRuntime) Apply([]byte) error {
	r.attempts++
	if r.reject {
		return errors.New("test rejection")
	}
	r.applies++
	r.running = true
	return nil
}
func (r *testRuntime) Close() error  { r.running = false; return nil }
func (r *testRuntime) Running() bool { return r.running }

func controlServer(t *testing.T, manager *nodeagent.Manager) (*httptest.Server, ControlTLS) {
	return controlHandlerServer(t, nodeagent.Handler(manager))
}

func controlHandlerServer(t *testing.T, handler http.Handler) (*httptest.Server, ControlTLS) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err = x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	identity, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{identity}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, ControlTLS{CA: string(caPEM), Certificate: string(certPEM), Key: string(keyPEM)}
}

func TestReconcileAdvancesExistingAgentAndPreservesAppliedOnFailure(t *testing.T) {
	db, node, client := fixture(t)
	runtime := &testRuntime{}
	manager := nodeagent.NewManager(1, nodeagent.FileStore{Directory: t.TempDir()}, runtime)
	t.Cleanup(func() { _ = manager.Close() })
	initial := nodeagent.Deployment{NodeID: 1, Revision: 4, Config: json.RawMessage(`{"inbounds":[],"outbounds":[{"type":"direct"}]}`), Users: []nodeagent.Access{}}
	if err := manager.Apply(initial); err != nil {
		t.Fatal(err)
	}
	server, identity := controlServer(t, manager)
	node.Address = server.URL
	node.ControlCA = identity.CA
	node.ControlCertificate = identity.Certificate
	node.ControlKey = identity.Key
	if err := db.Save(&node).Error; err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	db.First(&node, 1)
	if node.DesiredRevision != 5 || node.AppliedRevision != 5 || manager.Status().Revision != 5 {
		t.Fatal("controller did not continue existing agent revision")
	}
	if err := Reconcile(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if runtime.applies != 2 {
		t.Fatal("unchanged reconciliation unnecessarily reapplied deployment")
	}
	runtime.reject = true
	db.Model(&model.Node{}).Where("id = 1").Update("link_address", "changed.example")
	if err := Reconcile(context.Background(), 1); err == nil {
		t.Fatal("agent failure was reported as success")
	}
	db.First(&node, 1)
	if node.DesiredRevision != 6 || node.AppliedRevision != 5 || node.LastError == "" {
		t.Fatal("failed revision overwrote applied status")
	}
	attempts := runtime.attempts
	if err := Reconcile(context.Background(), 1); err == nil {
		t.Fatal("rejected revision was reported as applied")
	}
	if runtime.attempts != attempts {
		t.Fatal("rejected configuration repeatedly disrupted the last-good runtime")
	}
	endpoints, err := ClientInbounds(db, client)
	if err != nil || len(endpoints) != 1 || !strings.Contains(string(endpoints[0].Addrs), "first.example") {
		t.Fatal("failed apply broke existing publication", err)
	}
	runtime.reject = false
	if err := Save("nodes", "retry", json.RawMessage(`{"id":1}`), "test"); err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if runtime.attempts != attempts+1 {
		t.Fatal("explicit retry did not attempt a new deployment")
	}
	db.Model(&model.Client{}).Where("id = 1").Update("enable", false)
	if err := Reconcile(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	var saved model.Node
	db.First(&saved, 1)
	var s Snapshot
	_ = json.Unmarshal(saved.AppliedSnapshot, &s)
	if len(s.Deployment.Users) != 0 {
		t.Fatal("global client disable did not revoke node user")
	}
	public, _ := json.Marshal(saved)
	if strings.Contains(string(public), "PRIVATE KEY") || strings.Contains(string(public), "deployment") {
		t.Fatal("node API model exposed private state")
	}
	server.Close()
	previousApplied := saved.AppliedRevision
	db.Model(&model.Node{}).Where("id = 1").Update("link_address", "offline-edit.example")
	if err := Reconcile(context.Background(), 1); err == nil {
		t.Fatal("closed agent connection unexpectedly succeeded")
	}
	db.First(&saved, 1)
	if saved.DesiredRevision <= previousApplied || saved.AppliedRevision != previousApplied || saved.LastError != "control_unreachable" {
		t.Fatal("offline intent was not persisted separately from applied state")
	}
}
