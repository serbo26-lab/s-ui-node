package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/alireza0/s-ui/database/model"
	"gorm.io/gorm"
)

var errNodeFirewall = errors.New("node_firewall_failed")

// The panel uses its existing privileged SSH access. The agent keeps only
// CAP_NET_BIND_SERVICE and never receives firewall administration privileges.
func ensureNodeFirewall(ctx context.Context, db *gorm.DB, node model.Node, snapshot Snapshot) error {
	var install model.NodeInstallation
	if err := db.First(&install, "node_id = ?", node.Id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	if !install.Ready || install.OwnerID == "" || install.PrivateKey == "" {
		return nil
	}
	listeners := []listenerSocket{}
	for _, inbound := range snapshot.Inbounds {
		var options struct {
			Port      int               `json:"listen_port"`
			Transport listenerTransport `json:"transport"`
			Network   string            `json:"network"`
		}
		if err := json.Unmarshal(inbound.Options, &options); err != nil {
			return err
		}
		if options.Port > 0 {
			listeners = append(listeners, expandSocket(listenerSocket{Network: listenerNetwork(inbound.Type, options.Transport, options.Network), Port: options.Port})...)
		}
	}
	if len(listeners) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	client, err := connectSSH(ctx, &install, "", false)
	if err != nil {
		return errNodeFirewall
	}
	defer client.Close()
	script := provisionFirewallPython + `
import json,sys
p=json.load(sys.stdin)
configure_node_firewall(p['listeners'], 's-ui-node')
print(json.dumps({'configured':True}))
`
	_, err = remotePython(ctx, client, install.SSHUser, script, map[string]interface{}{"listeners": listeners})
	if err != nil {
		return errNodeFirewall
	}
	return nil
}

const provisionFirewallPython = `
def configure_node_firewall(listeners, name):
 import os,shutil,subprocess
 endpoints=sorted({(int(row['port']),row['network']) for row in listeners})
 if any(not 1<=port<=65535 or network not in ('tcp','udp') for port,network in endpoints):
  raise ValueError('invalid firewall listener')
 def run(args,check=True):
  return subprocess.run(args,check=check,capture_output=True,text=True,timeout=15,env=dict(os.environ,LC_ALL='C'))
 ufw=shutil.which('ufw')
 if ufw and 'Status: active' in run([ufw,'status']).stdout:
  for port,network in endpoints:run([ufw,'allow',str(port)+'/'+network,'comment',name])
 firewall=shutil.which('firewall-cmd')
 if not firewall or run([firewall,'--state'],check=False).returncode!=0:return
 zones=[line.split()[0] for line in run([firewall,'--get-active-zones']).stdout.splitlines() if line and not line[0].isspace()]
 if not zones:zones=[run([firewall,'--get-default-zone']).stdout.strip()]
 for zone in zones:
  for permanent in ([],['--permanent']):
   for port,network in endpoints:
    prefix=[firewall,*permanent,'--zone='+zone]
    endpoint=str(port)+'/'+network
    query=run([*prefix,'--query-port='+endpoint],check=False)
    if query.returncode==1:run([*prefix,'--add-port='+endpoint])
    elif query.returncode!=0:raise RuntimeError('firewall port query failed')
`
