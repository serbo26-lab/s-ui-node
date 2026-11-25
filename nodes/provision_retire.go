package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
)

type retireTarget struct {
	IP      string
	Port    int
	User    string
	HostKey string
}

var retirementAttempts sync.Map

func retirementTargets(raw json.RawMessage) []retireTarget {
	var targets []retireTarget
	if len(raw) == 0 {
		return targets
	}
	if json.Unmarshal(raw, &targets) == nil {
		return targets
	}
	var old retireTarget
	if json.Unmarshal(raw, &old) == nil && old.IP != "" {
		return []retireTarget{old}
	}
	return nil
}
func rememberPreviousHost(current *model.NodeInstallation, previous model.NodeInstallation) {
	targets := retirementTargets(current.PreviousTarget)
	for _, target := range targets {
		if target.IP == previous.IP && target.Port == previous.SSHPort && target.User == previous.SSHUser {
			return
		}
	}
	targets = append(targets, retireTarget{previous.IP, previous.SSHPort, previous.SSHUser, previous.HostKey})
	current.PreviousTarget, _ = json.Marshal(targets)
}
func retirePreviousHost(ctx context.Context, current *model.NodeInstallation) error {
	remaining := []retireTarget{}
	for _, target := range retirementTargets(current.PreviousTarget) {
		if target.IP == current.IP {
			continue
		}
		if err := retireOneHost(ctx, *current, target); err != nil {
			remaining = append(remaining, target)
		}
	}
	current.PreviousTarget = nil
	if len(remaining) > 0 {
		current.PreviousTarget, _ = json.Marshal(remaining)
		return errors.New("old_server_retirement_pending")
	}
	return nil
}
func retireOneHost(ctx context.Context, current model.NodeInstallation, target retireTarget) error {
	previous := current
	previous.IP, previous.SSHPort, previous.SSHUser, previous.HostKey = target.IP, target.Port, target.User, target.HostKey
	short, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	client, err := connectSSH(short, &previous, "", false)
	if err != nil {
		return err
	}
	defer client.Close()
	script := provisionFirewallPython + fmt.Sprintf(`import json,subprocess
from pathlib import Path
name='s-ui-node-%d'
unit=Path('/etc/systemd/system')/(name+'.service')
if unit.exists():
 if '# S-UI managed node %d' not in unit.read_text():raise SystemExit('not our service')
 subprocess.run(['systemctl','disable','--now',name],check=True,capture_output=True)
release_node_firewall(name)
print(json.dumps({'retired':True}))
`, current.NodeId, current.NodeId)
	_, err = remotePython(short, client, previous.SSHUser, script, nil)
	return err
}
func retryPreviousRetirement(ctx context.Context, current model.NodeInstallation) {
	if last, ok := retirementAttempts.Load(current.NodeId); ok && time.Since(last.(time.Time)) < time.Minute {
		return
	}
	retirementAttempts.Store(current.NodeId, time.Now())
	go func() {
		lock := provisionOperationLock(current.NodeId)
		lock.Lock()
		defer lock.Unlock()
		if jobRunning(current.NodeId) {
			return
		}
		var fresh model.NodeInstallation
		if dbInstall(current.NodeId, &fresh) != nil || fresh.IP != current.IP {
			return
		}
		original := append(json.RawMessage(nil), fresh.PreviousTarget...)
		err := retirePreviousHost(ctx, &fresh)
		if database.GetDB().Model(&model.NodeInstallation{}).Where("node_id = ? AND previous_target = ?", fresh.NodeId, original).Update("previous_target", fresh.PreviousTarget).Error == nil && err == nil {
			database.GetDB().Model(&model.NodeJob{}).Where("node_id = ? AND warning = ?", fresh.NodeId, "old_server_retirement_pending").Update("warning", "")
		}
	}()
}
