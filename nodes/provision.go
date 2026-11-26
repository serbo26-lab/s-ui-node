package nodes

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/nodeagent"
	"gorm.io/gorm"
)

type ProvisionRequest struct {
	ModelVersion       int              `json:"model_version,omitempty"`
	RequestKey         string           `json:"request_key,omitempty"`
	ExpectedVersion    *uint64          `json:"expected_version,omitempty"`
	Domain             *ProvisionDomain `json:"domain,omitempty"`
	NodeId             uint             `json:"node_id"`
	Name               string           `json:"name"`
	IP                 string           `json:"ip"`
	SSHPort            int              `json:"ssh_port"`
	SSHUser            string           `json:"ssh_user"`
	Password           string           `json:"password"`
	Protocols          []string         `json:"protocols"`
	TemplateId         uint             `json:"template_id"`
	InboundTemplateIds []uint           `json:"inbound_template_ids,omitempty"`
	Action             string           `json:"action"`
	ReplaceHostKey     bool             `json:"replace_host_key"`
}

var provisionJobs sync.Map
var provisionSlots = make(chan struct{}, 2)
var provisionOperations sync.Map

func provisionOperationLock(id uint) *sync.Mutex {
	value, _ := provisionOperations.LoadOrStore(id, &sync.Mutex{})
	return value.(*sync.Mutex)
}

var provisionLifecycle sync.RWMutex
var provisionParent context.Context = context.Background()

func dbInstall(id uint, i *model.NodeInstallation) error {
	return database.GetDB().First(i, whereNodeID, id).Error
}
func jobRunning(id uint) bool {
	_, ok := provisionJobs.Load(id)
	return ok || agentUpgradeRunning(id)
}
func supportedProtocols(values []string, extended bool) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("protocol_required")
	}
	seen := map[string]bool{}
	result := []string{}
	for _, p := range values {
		if !nodeagent.SupportsInbound(p, extended) {
			return nil, errors.New("unsupported_node_protocol")
		}
		if !seen[p] {
			result = append(result, p)
			seen[p] = true
		}
	}
	return result, nil
}
func normalizeProvision(r *ProvisionRequest) error {
	provisionDefaults(r)
	ip := net.ParseIP(r.IP)
	if r.Name == "" || len([]rune(r.Name)) > 80 {
		return errors.New("node_name_required")
	}
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("invalid_node_ip")
	}
	if r.SSHPort < 1 || r.SSHPort > 65535 || strings.ContainsAny(r.SSHUser, "\r\n\x00 ") || r.SSHUser == "" {
		return errors.New("invalid_ssh_access")
	}
	if r.Action != "install" && r.Action != "recover" && r.Action != "update" {
		return errors.New("invalid_install_action")
	}
	if r.NodeId == 0 && r.Action != "install" {
		return errors.New("invalid_install_action")
	}
	if r.ReplaceHostKey && (r.Action != "recover" || r.Password == "") {
		return errors.New("recovery_password_required")
	}
	if r.ModelVersion == 2 && len(r.Protocols) == 0 {
		return nil
	}
	var err error
	r.Protocols, err = supportedProtocols(r.Protocols, r.ModelVersion == 2)
	return err
}

func StartProvision(r ProvisionRequest, actor string) (model.NodeJob, error) {
	if r.ModelVersion == 2 {
		return startLiveProvision(r, actor)
	}
	var job model.NodeJob
	if err := prepareLegacyProvisionRequest(&r); err != nil {
		return job, err
	}
	var install model.NodeInstallation
	err := database.GetDB().Transaction(func(tx *gorm.DB) error {
		var node model.Node
		if err := loadLegacyProvisionTarget(tx, r, &node, &install); err != nil {
			return err
		}
		var duplicates int64
		if err := tx.Model(&model.Node{}).Where("name = ? AND id <> ?", r.Name, r.NodeId).Count(&duplicates).Error; err != nil {
			return err
		}
		if duplicates > 0 {
			return errors.New("node_name_exists")
		}
		if err := createLegacyProvisionTarget(tx, r, &node, &install); err != nil {
			return err
		}
		var active int64
		if err := tx.Model(&model.NodeJob{}).Where("node_id = ? AND state IN ?", node.Id, []string{"queued", "running"}).Count(&active).Error; err != nil {
			return err
		}
		if active > 0 {
			return errors.New("node_job_running")
		}
		entropy := make([]byte, 16)
		if _, err := rand.Read(entropy); err != nil {
			return err
		}
		job = model.NodeJob{Id: hex.EncodeToString(entropy), NodeId: node.Id, Action: r.Action, State: "queued", Stage: "queued", Created: time.Now().Unix(), Updated: time.Now().Unix(), Events: json.RawMessage(`[]`)}
		if err := tx.Create(&job).Error; err != nil {
			return err
		}
		return tx.Create(&model.Changes{DateTime: time.Now().Unix(), Actor: actor, Key: "node-provision", Action: r.Action, Obj: json.RawMessage(`{"job":"` + job.Id + `"}`)}).Error
	})
	if err != nil {
		return job, err
	}
	provisionJobs.Store(job.NodeId, true)
	go runProvision(job, r, install)
	return job, nil
}

func jobStage(job *model.NodeJob, stage, state, code string) {
	type event struct {
		Time  int64  `json:"time"`
		Stage string `json:"stage"`
		State string `json:"state"`
		Error string `json:"error,omitempty"`
	}
	var events []event
	_ = json.Unmarshal(job.Events, &events)
	events = append(events, event{time.Now().Unix(), stage, state, code})
	job.Events, _ = json.Marshal(events)
	job.Stage, job.State, job.Error, job.Updated = stage, state, code, time.Now().Unix()
	database.GetDB().Save(job)
}

func runProvision(job model.NodeJob, r ProvisionRequest, install model.NodeInstallation) {
	defer provisionJobs.Delete(job.NodeId)
	operation := provisionOperationLock(job.NodeId)
	operation.Lock()
	defer operation.Unlock()
	provisionLifecycle.RLock()
	parent := provisionParent
	provisionLifecycle.RUnlock()
	ctx, cancel := context.WithTimeout(parent, 9*time.Minute)
	defer cancel()
	select {
	case provisionSlots <- struct{}{}:
		defer func() { <-provisionSlots }()
	case <-ctx.Done():
		jobStage(&job, "queued", "failed", "install_timeout")
		return
	}
	fail := func(code string) { jobStage(&job, job.Stage, "failed", code) }
	jobStage(&job, "ssh", "running", "")
	oldIP := install.IP
	previous := install
	install.IP, install.SSHPort, install.SSHUser = r.IP, r.SSHPort, r.SSHUser
	if oldIP != "" && oldIP != r.IP {
		if previous.Ready {
			rememberPreviousHost(&install, previous)
		}
		if r.Password != "" {
			install.HostKey = ""
		}
	}
	hadPassword := r.Password != ""
	client, err := connectSSH(ctx, &install, r.Password, r.ReplaceHostKey)
	r.Password = ""
	if err != nil {
		fail(err.Error())
		return
	}
	defer client.Close()
	if !hadPassword && renameOnly(r, previous) {
		finishLegacyRename(ctx, &job, r)
		return
	}
	jobStage(&job, "preflight", "running", "")
	host, err := inspectProvisionHost(ctx, client, r.SSHUser)
	if err != nil {
		fail(liveInstallError(err))
		return
	}
	artifact, hash, err := agentArtifact(host.architecture)
	if err != nil {
		fail("agent_build_unavailable")
		return
	}
	jobStage(&job, "dependencies", "running", "")
	if err = ensureRemotePython(ctx, client, r.SSHUser, host); err != nil {
		fail(liveInstallError(err))
		return
	}
	jobStage(&job, "inspect", "running", "")
	ports := map[string]int{}
	if r.NodeId != 0 {
		var inbounds []model.NodeInbound
		database.GetDB().Where(whereNodeID, job.NodeId).Find(&inbounds)
		for _, i := range inbounds {
			var o struct {
				Port int `json:"listen_port"`
			}
			_ = json.Unmarshal(i.Options, &o)
			ports[i.Type] = o.Port
		}
	}
	response, err := remotePython(ctx, client, r.SSHUser, inspectScript(job.NodeId), map[string]interface{}{"protocols": r.Protocols, "ports": ports, "control_port": install.ControlPort, "recover": oldIP == r.IP && r.NodeId != 0})
	if err != nil {
		fail("server_inspection_failed")
		return
	}
	var server struct {
		Arch        string         `json:"arch"`
		Ports       map[string]int `json:"ports"`
		ControlPort int            `json:"control_port"`
		Firewall    string         `json:"firewall"`
	}
	if json.Unmarshal(response, &server) != nil || server.ControlPort == 0 {
		fail("server_inspection_failed")
		return
	}
	if server.Arch != host.architecture {
		fail("unsupported_architecture")
		return
	}
	node, err := prepareLegacyInstallIdentity(ctx, &job, r, &install, server.ControlPort)
	if err != nil {
		fail(err.Error())
		return
	}
	jobStage(&job, "install", "running", "")
	if err = uploadAgent(ctx, client, r.SSHUser, job.NodeId, artifact, hash); err != nil {
		fail("agent_upload_failed")
		return
	}
	key, e := openSecret(install.PrivateKey)
	if e != nil {
		fail("state_key_unavailable")
		return
	}
	signer, e := parseProvisionSSHKey(key)
	if e != nil {
		fail("identity_failed")
		return
	}
	cert, e := openSecret(install.ServerCertificate)
	if e != nil {
		fail("state_key_unavailable")
		return
	}
	serverKey, e := openSecret(install.ServerKey)
	if e != nil {
		fail("state_key_unavailable")
		return
	}
	// Save the bootstrap key before remote service changes: a retry can use it
	// after a disconnected browser or panel restart, without retaining passwords.
	if !install.Ready {
		err = database.GetDB().Transaction(func(tx *gorm.DB) error {
			if e := tx.Model(&model.Node{}).Where("id = ?", node.Id).Updates(map[string]interface{}{"control_ca": node.ControlCA, "control_certificate": node.ControlCertificate, "control_key": node.ControlKey}).Error; e != nil {
				return e
			}
			return tx.Save(&install).Error
		})
	}
	if err != nil {
		fail("install_state_failed")
		return
	}
	listeners := []listenerSocket{}
	for protocol, port := range server.Ports {
		listeners = append(listeners, expandSocket(listenerSocket{Network: listenerNetwork(protocol, listenerTransport{}), Port: port})...)
	}
	input := map[string]interface{}{"id": job.NodeId, "ssh_user": r.SSHUser, "control_port": install.ControlPort, "sha256": hash, "ca": node.ControlCA, "certificate": cert, "key": serverKey, "authorized_key": signer, "listeners": listeners}
	if err = installRemoteAgent(ctx, client, r.SSHUser, installAgentScript, input); err != nil {
		fail(liveInstallError(err))
		return
	}
	jobStage(&job, "configure", "running", "")
	ca, controllerCert, controllerKey := node.ControlCA, node.ControlCertificate, node.ControlKey
	err = database.GetDB().Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&node, job.NodeId).Error; err != nil {
			return err
		}
		node.ControlCA, node.ControlCertificate, node.ControlKey = ca, controllerCert, controllerKey
		if err := tx.Save(&install).Error; err != nil {
			return err
		}
		// Existing identities are loaded again above; new nodes get their generated
		// controller pair from local variables retained outside the transaction.
		return configureManagedNode(tx, &node, &install, r, server.Ports)
	})
	if err != nil {
		fail("configuration_failed")
		return
	}
	verifyLegacyProvision(ctx, &job, r, &install)
}

func initializeProvisionJobs(ctx context.Context) {
	provisionLifecycle.Lock()
	provisionParent = ctx
	provisionLifecycle.Unlock()
	database.GetDB().Model(&model.NodeJob{}).Where("state IN ?", []string{"running", "queued"}).Updates(map[string]interface{}{"state": "interrupted", "error": "panel_restarted", "updated": time.Now().Unix()})
	resumeLiveProvisionJobs(ctx)
}

func provisionDefaults(r *ProvisionRequest) {
	r.Name = strings.TrimSpace(r.Name)
	r.IP = strings.TrimSpace(r.IP)
	r.SSHUser = strings.TrimSpace(r.SSHUser)
	if r.SSHPort == 0 {
		r.SSHPort = 22
	}
	if r.SSHUser == "" {
		r.SSHUser = "root"
	}
	if r.Action == "" {
		r.Action = "install"
	}
}

func prepareLegacyProvisionRequest(r *ProvisionRequest) error {
	if err := prepareLegacyTemplateSelection(r); err != nil {
		return err
	}
	if err := normalizeProvision(r); err != nil {
		return err
	}
	needsTLS := false
	for _, p := range r.Protocols {
		if p != "vless" {
			needsTLS = true
		}
	}
	if needsTLS {
		settings, _ := loadAutomation()
		if settings.DomainSuffix == "" || settings.DNSToken == "" {
			return errors.New("dns_profile_required")
		}
	}
	if r.NodeId == 0 && r.Password == "" {
		return errors.New("ssh_password_required")
	}
	return nil
}

func loadLegacyProvisionTarget(tx *gorm.DB, r ProvisionRequest, node *model.Node, install *model.NodeInstallation) error {
	if r.NodeId != 0 {
		if err := tx.First(node, r.NodeId).Error; err != nil {
			return err
		}
		if node.TemplateTargetVersion > 0 {
			return errors.New("live_template_installer_not_ready")
		}
		if err := tx.First(install, whereNodeID, node.Id).Error; err != nil {
			return errors.New("manual_node_requires_advanced_settings")
		}
		if jobRunning(node.Id) {
			return errors.New("node_job_running")
		}
		if len(install.PreviousTarget) > 0 && install.IP != r.IP {
			return errors.New("old_server_retirement_pending")
		}
	}
	return nil
}

func createLegacyProvisionTarget(tx *gorm.DB, r ProvisionRequest, node *model.Node, install *model.NodeInstallation) error {
	if r.NodeId == 0 {
		*node = model.Node{Name: r.Name, LinkAddress: r.IP, Address: "https://127.0.0.1:16500", Enable: false, Config: json.RawMessage(`{}`)}
		if err := tx.Create(node).Error; err != nil {
			return err
		}
		*install = model.NodeInstallation{NodeId: node.Id, IP: r.IP, SSHPort: r.SSHPort, SSHUser: r.SSHUser}
		install.Protocols, _ = json.Marshal(r.Protocols)
		if err := tx.Create(install).Error; err != nil {
			return err
		}
	}
	return nil
}

func finishLegacyRename(ctx context.Context, job *model.NodeJob, r ProvisionRequest) {
	jobStage(job, "configure", "running", "")
	if err := database.GetDB().Model(&model.Node{}).Where("id = ?", job.NodeId).Updates(map[string]interface{}{"name": r.Name, "template_id": r.TemplateId, "desired_fingerprint": "", "rejected_revision": 0}).Error; err != nil {
		failLegacyJob(job, "configuration_failed")
		return
	}
	if err := Reconcile(ctx, job.NodeId); err != nil {
		failLegacyJob(job, "control_unreachable")
		return
	}
	var current model.Node
	database.GetDB().First(&current, job.NodeId)
	if !managedCertificatesReady(current, r.Protocols) {
		failLegacyJob(job, "certificate_unavailable")
		return
	}
	jobStage(job, "ready", "succeeded", "")
}

func verifyLegacyProvision(ctx context.Context, job *model.NodeJob, r ProvisionRequest, install *model.NodeInstallation) {
	jobStage(job, "verify", "running", "")
	for ctx.Err() == nil {
		if err := Reconcile(ctx, job.NodeId); err == nil {
			var current model.Node
			database.GetDB().First(&current, job.NodeId)
			if managedCertificatesReady(current, r.Protocols) {
				if err := retirePreviousHost(ctx, install); err != nil {
					job.Warning = "old_server_retirement_pending"
				}
				install.Ready = true
				database.GetDB().Save(install)
				jobStage(job, "ready", "succeeded", "")
				return
			}
			if job.Stage != "certificate" {
				jobStage(job, "certificate", "running", "")
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	if ctx.Err() == context.Canceled {
		jobStage(job, job.Stage, "interrupted", "panel_restarted")
	} else {
		failLegacyJob(job, "install_timeout")
	}
}

func failLegacyJob(job *model.NodeJob, code string) { jobStage(job, job.Stage, "failed", code) }

func prepareLegacyTemplateSelection(r *ProvisionRequest) error {
	if r.NodeId != 0 {
		var node model.Node
		if err := database.GetDB().First(&node, r.NodeId).Error; err != nil {
			return err
		}
		if node.TemplateTargetVersion > 0 {
			return errors.New("live_template_installer_not_ready")
		}
	}
	if r.TemplateId != 0 {
		var template model.NodeTemplate
		if err := database.GetDB().First(&template, r.TemplateId).Error; err != nil {
			return err
		}
		if template.SchemaVersion == 1 {
			return errors.New("versioned_template_runtime_not_ready")
		}
	}
	if r.TemplateId != 0 && len(r.Protocols) == 0 {
		var t model.NodeTemplate
		if err := database.GetDB().First(&t, r.TemplateId).Error; err != nil {
			return err
		}
		_ = json.Unmarshal(t.Protocols, &r.Protocols)
	}
	return nil
}

func prepareLegacyInstallIdentity(ctx context.Context, job *model.NodeJob, r ProvisionRequest, install *model.NodeInstallation, controlPort int) (model.Node, error) {
	var node model.Node
	if install.PrivateKey == "" {
		private, _, e := newSSHKey()
		if e != nil {
			return node, errors.New("identity_failed")
		}
		install.PrivateKey, e = sealSecret(private)
		if e != nil {
			return node, errors.New("state_key_unavailable")
		}
	}
	install.NodeId, install.ControlPort = job.NodeId, controlPort
	install.Protocols, _ = json.Marshal(r.Protocols)
	if database.GetDB().First(&node, job.NodeId).Error != nil {
		return node, errors.New("node_missing")
	}
	// Generate control trust only once. Recovery reinstalls the same identity,
	// preserving node/inbound IDs and all customer keys and subscriptions.
	if install.ServerCertificate == "" {
		if err := newControlIdentity(&node, install); err != nil {
			return node, errors.New("identity_failed")
		}
	}
	if install.Domain == "" {
		settings, _ := loadAutomation()
		if settings.DomainSuffix != "" {
			install.Domain = automaticDomain(job.NodeId, settings.DomainSuffix)
		}
	}
	jobStage(job, "dns", "running", "")
	if install.Domain != "" {
		if err := ensureNodeDNS(ctx, install); err != nil {
			return node, err
		}
	}
	return node, nil
}
