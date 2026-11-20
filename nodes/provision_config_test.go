package nodes

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/alireza0/s-ui/database/model"
)

func TestProvisionStartCreatesOneNodeInstallationAndJob(t *testing.T) {
	db, _, _ := fixture(t)
	job, err := StartProvision(ProvisionRequest{Name: "Bootstrap", IP: "127.0.0.1", SSHPort: 1, SSHUser: "root", Password: "never-persist-this-password", Protocols: []string{"vless"}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var current model.NodeJob
		db.First(&current, "id = ?", job.Id)
		if current.State == "failed" {
			if jobRunning(job.NodeId) {
				time.Sleep(time.Millisecond)
				continue
			}
			var installations int64
			db.Model(&model.NodeInstallation{}).Where("node_id = ?", job.NodeId).Count(&installations)
			if installations != 1 {
				t.Fatalf("installation count %d", installations)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("background job did not terminate")
}

func TestProvisionRecoveryRetainsInboundIDsCredentialsAndAssignments(t *testing.T) {
	db, node, client := fixture(t)
	var before model.NodeInbound
	db.First(&before, "node_id = ?", node.Id)
	install := model.NodeInstallation{NodeId: node.Id, IP: "203.0.113.99", Domain: "n-1.nodes.example", ControlPort: 16500, Ready: true}
	if err := db.Create(&install).Error; err != nil {
		t.Fatal(err)
	}
	request := ProvisionRequest{NodeId: node.Id, Name: "Amsterdam", IP: install.IP, Protocols: []string{"vless"}}
	if err := configureManagedNode(db, &node, &install, request, map[string]int{"vless": 14443}); err != nil {
		t.Fatal(err)
	}
	var after model.NodeInbound
	if err := db.First(&after, before.Id).Error; err != nil {
		t.Fatal(err)
	}
	var old, new map[string]interface{}
	json.Unmarshal(before.Options, &old)
	json.Unmarshal(after.Options, &new)
	if string(mustJSON(old["tls"])) != string(mustJSON(new["tls"])) {
		t.Fatal("recovery replaced existing VPN keys")
	}
	var binding model.ClientNodeInbound
	if err := db.First(&binding, "client_id = ? AND node_inbound_id = ?", client.Id, before.Id).Error; err != nil {
		t.Fatal(err)
	}
	var preserved model.Client
	db.First(&preserved, client.Id)
	if string(preserved.Config) != string(client.Config) {
		t.Fatal("customer credentials changed")
	}
	db.First(&node, node.Id)
	if node.Name != "Amsterdam" || node.LinkAddress != install.Domain {
		t.Fatal("node publication not updated")
	}
}
func mustJSON(v interface{}) []byte { b, _ := json.Marshal(v); return b }
