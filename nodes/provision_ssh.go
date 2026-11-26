package nodes

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/alireza0/s-ui/database/model"
	"golang.org/x/crypto/ssh"
)

func connectSSH(ctx context.Context, install *model.NodeInstallation, password string, replaceHost bool) (*ssh.Client, error) {
	auth := []ssh.AuthMethod{}
	if password != "" {
		auth = append(auth, ssh.Password(password), passwordSSHAuth(password))
	}
	if install.PrivateKey != "" {
		key, err := openSecret(install.PrivateKey)
		if err != nil {
			return nil, errors.New("state_key_unavailable")
		}
		signer, err := ssh.ParsePrivateKey([]byte(key))
		if err != nil {
			return nil, err
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if len(auth) == 0 {
		return nil, errors.New("ssh_password_required")
	}
	observed := ""
	cfg := &ssh.ClientConfig{User: install.SSHUser, Auth: auth, Timeout: 12 * time.Second, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		observed = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		if install.HostKey != "" && install.HostKey != observed && !replaceHost {
			return errors.New("ssh_host_changed")
		}
		return nil
	}}
	address := net.JoinHostPort(install.IP, strconv.Itoa(install.SSHPort))
	conn, err := (&net.Dialer{Timeout: 12 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, errors.New("ssh_unreachable")
	}
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	deadline := time.Now().Add(20 * time.Second)
	if until, ok := ctx.Deadline(); ok && until.Before(deadline) {
		deadline = until
	}
	_ = conn.SetDeadline(deadline)
	c, ch, req, err := ssh.NewClientConn(conn, address, cfg)
	if err != nil {
		stopCancellation()
		conn.Close()
		if strings.Contains(err.Error(), "ssh_host_changed") {
			return nil, errors.New("ssh_host_changed")
		}
		return nil, errors.New("ssh_auth_failed")
	}
	_ = conn.SetDeadline(time.Time{})
	install.HostKey = observed
	client := ssh.NewClient(c, ch, req)
	go func() {
		_ = client.Wait()
		stopCancellation()
	}()
	return client, nil
}

// Only generated Python and structured stdin are sent. User strings are never
// interpolated into a shell command or put in argv/process listings.
func remotePython(ctx context.Context, client *ssh.Client, user, script string, input interface{}) ([]byte, error) {
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	return remoteStream(ctx, client, user, script, bytes.NewReader(payload))
}

func remoteStream(ctx context.Context, client *ssh.Client, user, script string, input io.Reader) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			session.Close()
		case <-done:
		}
	}()
	code := `import base64;exec(base64.b64decode("` + base64.StdEncoding.EncodeToString([]byte(script)) + `"))`
	command := "python3 -c '" + code + "'"
	if user != "root" {
		command = "sudo -n " + command
	}
	var output limitedBuffer
	session.Stdout = &output
	session.Stderr = io.Discard
	session.Stdin = input
	if err = session.Run(command); err != nil {
		return nil, errors.New("remote_command_failed")
	}
	if output.Len() > 1<<20 {
		return nil, errors.New("remote_response_invalid")
	}
	return output.Bytes(), nil
}

func inspectScript(id uint) string {
	prefix := fmt.Sprintf("import json,os,platform,shutil,subprocess,socket\nfrom pathlib import Path\nif os.geteuid()!=0 or not Path('/run/systemd/system').exists():raise SystemExit('root/systemd required')\npayload=json.load(__import__('sys').stdin)\nunit=Path('/etc/systemd/system/s-ui-node-%d.service')\nowned=unit.exists() and '# S-UI managed node %d' in unit.read_text()\npayload['recover']=payload.get('recover') and owned\n", id, id)
	// The inspection code consumes only the locally generated structured payload.
	script := strings.Replace(remoteInspection, "p=json.load(__import__('sys').stdin)", "p=payload", 1)
	return prefix + script
}

const remoteInspection = `import json,socket,platform,subprocess
p=json.load(__import__('sys').stdin)
ports={}
for proto in p['protocols']:
 kind=socket.SOCK_DGRAM if proto in ('tuic','hysteria2') else socket.SOCK_STREAM
 old=p.get('ports',{}).get(proto)
 candidates=[old] if old else [443,8443,2053,2083,2087,2096]+list(range(20000,20100))
 for candidate in candidates:
  if not candidate or candidate in ports.values():continue
  with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as test_tcp:
   pass
  with socket.socket(socket.AF_INET,kind) as s:
   try:s.bind(('0.0.0.0',candidate))
   except OSError:
    if old and p.get('recover'):ports[proto]=candidate;break
    continue
  ports[proto]=candidate;break
 if proto not in ports:raise SystemExit('VPN port occupied')
control=p.get('control_port',0)
if not control:
 for candidate in range(16500,16600):
  with socket.socket() as s:
   try:s.bind(('127.0.0.1',candidate));control=candidate;break
   except OSError:pass
 if not control:raise SystemExit('no control port')
arch={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine(),'unsupported')
print(json.dumps({'arch':arch,'ports':ports,'control_port':control}))
`

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 2<<20 {
		return 0, errors.New("remote output too large")
	}
	return b.Buffer.Write(p)
}

func sshFingerprint(key string) string {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(k)
}

func managedTransport(ctx context.Context, nodeID uint) (*ssh.Client, *model.NodeInstallation, error) {
	var i model.NodeInstallation
	if err := dbInstall(nodeID, &i); err != nil {
		return nil, nil, err
	}
	client, err := connectSSH(ctx, &i, "", false)
	if err != nil {
		return nil, nil, err
	}
	return client, &i, nil
}

func controlAddress(port int) string { return fmt.Sprintf("https://127.0.0.1:%d", port) }

func passwordSSHAuth(password string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(_, _ string, q []string, echo []bool) ([]string, error) {
		a := make([]string, len(q))
		for i := range a {
			if echo[i] {
				return nil, errors.New("unexpected SSH challenge")
			}
			a[i] = password
		}
		return a, nil
	})
}
