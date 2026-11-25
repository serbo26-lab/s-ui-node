package nodes

import (
	"os/exec"
	"strings"
	"testing"
)

func TestProvisionFirewallRules(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("firewall script regression requires python3")
	}
	const checks = `
import shutil,subprocess
from types import SimpleNamespace
calls=[]
opened=set()
active=True
def fake_run(args,**kwargs):
 calls.append(args)
 assert kwargs['timeout']==15
 if args[0]=='ufw':return SimpleNamespace(returncode=0,stdout='Status: inactive')
 if '--state' in args:return SimpleNamespace(returncode=0 if active else 252,stdout='running')
 if '--get-active-zones' in args:return SimpleNamespace(returncode=0,stdout='public\n  interfaces: eth0\ninternal\n  interfaces: eth1\n')
 key=tuple(arg for arg in args if not arg.startswith(('--query-port=','--add-port=')))
 endpoint=args[-1].split('=',1)[1]
 if '--query-port=' in args[-1]:return SimpleNamespace(returncode=0 if (key,endpoint) in opened else 1,stdout='')
 assert '--add-port=' in args[-1]
 opened.add((key,endpoint))
 return SimpleNamespace(returncode=0,stdout='')
subprocess.run=fake_run
shutil.which=lambda name:name
listeners=[{'port':443,'network':'tcp'},{'port':443,'network':'udp'},{'port':443,'network':'tcp'}]
configure_node_firewall(listeners,'node-test')
assert len(opened)==8
before=len([a for a in calls if a[-1].startswith('--add-port=')])
configure_node_firewall(listeners,'node-test')
assert len([a for a in calls if a[-1].startswith('--add-port=')])==before
assert not any('--reload' in args or '--complete-reload' in args for args in calls)
active=False
calls.clear()
configure_node_firewall(listeners,'node-test')
assert not any(a[-1].startswith(('--query-port=','--add-port=')) for a in calls)
try:
 configure_node_firewall([{'port':443,'network':'both'}],'node-test')
 raise AssertionError('invalid network accepted')
except ValueError:pass
`
	cmd := exec.CommandContext(t.Context(), python, "-")
	cmd.Stdin = strings.NewReader(provisionFirewallPython + checks)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("firewall rules failed: %s %v", output, err)
	}
}
