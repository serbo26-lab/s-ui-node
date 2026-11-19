package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/alireza0/s-ui/database/model"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const portInspectionTimeout = 20 * time.Second

var (
	errListenerOccupied     = errors.New("node_listener_port_occupied")
	errListenerReserved     = errors.New("node_listener_port_reserved")
	errAutoPortsExhausted   = errors.New("node_port_allocation_exhausted")
	errPortInspection       = errors.New("node_port_inspection_failed")
	errListenerDraftChanged = errors.New("listener_draft_changed")
)

type listenerSocket struct {
	Network string `json:"network"`
	Port    int    `json:"port"`
}

type listenerRequest struct {
	Key            string
	listenerSocket // Zero port means a new automatic assignment.
}

var automaticListenerPorts = func() []int {
	ports := []int{443}
	for port := 8443; port <= 65535; port += 1000 {
		ports = append(ports, port)
	}
	return ports
}()

type listenerTransport struct {
	Type string `json:"type"`
}

func listenerNetwork(protocol string, transport listenerTransport, network ...string) string {
	if protocol == "tuic" || protocol == "hysteria2" || protocol == "hysteria" || transport.Type == "quic" {
		return "udp"
	}
	if protocol == "shadowsocks" || protocol == "naive" {
		if len(network) > 0 && (network[0] == "udp" || network[0] == "tcp") {
			return network[0]
		}
		return "both"
	}
	return "tcp"
}

func expandSocket(socket listenerSocket) []listenerSocket {
	if socket.Network == "both" {
		return []listenerSocket{{Network: "tcp", Port: socket.Port}, {Network: "udp", Port: socket.Port}}
	}
	return []listenerSocket{socket}
}

func listenerRequests(tx *gorm.DB, node model.Node, spec TemplateSpec, overrides map[string][]SpecOverride) ([]listenerRequest, error) {
	var requests []listenerRequest
	for _, entry := range spec.Entries {
		if !entry.Enable {
			continue
		}
		var options struct {
			Port      json.RawMessage   `json:"listen_port"`
			Transport listenerTransport `json:"transport"`
			Network   string            `json:"network"`
		}
		if err := json.Unmarshal(entry.Options, &options); err != nil {
			return nil, err
		}
		port := options.Port
		source, sourced := entry.Sources["/listen_port"]
		transportSource, transportSourced := entry.Sources["/transport"]
		typeSource, typeSourced := entry.Sources["/transport/type"]
		clearTransportType := false
		for _, override := range overrides[entry.Key] {
			if override.Path == "/network" {
				options.Network = ""
				if override.Operation == "set" && (override.Source.Kind != "literal" || json.Unmarshal(override.Source.Value, &options.Network) != nil) {
					return nil, errors.New("invalid node network")
				}
			}
			if override.Path == "/listen_port" {
				source, sourced = override.Source, override.Operation == "set"
				port = nil
			}
			if override.Path == "/transport" {
				transportSource, transportSourced = override.Source, override.Operation == "set"
				typeSourced = false
				options.Transport = listenerTransport{}
			}
			if override.Path == "/transport/type" {
				typeSource, typeSourced = override.Source, override.Operation == "set"
				clearTransportType = !typeSourced
			}
		}
		if transportSourced && (transportSource.Kind != "literal" || json.Unmarshal(transportSource.Value, &options.Transport) != nil) {
			return nil, errors.New("invalid_listener_transport_source")
		}
		if clearTransportType {
			options.Transport.Type = ""
		}
		if typeSourced && (typeSource.Kind != "literal" || json.Unmarshal(typeSource.Value, &options.Transport.Type) != nil) {
			return nil, errors.New("invalid_listener_transport_source")
		}
		request := listenerRequest{Key: entry.Key, listenerSocket: listenerSocket{Network: listenerNetwork(entry.Protocol, options.Transport, options.Network)}}
		if sourced {
			switch {
			case source.Kind == "literal":
				port = source.Value
			case source.Kind == "node_generated" && source.Purpose == "listen_port":
				var err error
				port, err = loadGeneratedValue(tx, node.Id, entry.Key, "listen_port")
				if errors.Is(err, gorm.ErrRecordNotFound) {
					requests = append(requests, request)
					continue
				}
				if err != nil {
					return nil, err
				}
			default:
				return nil, errors.New("invalid_listener_port_source")
			}
		}
		if json.Unmarshal(port, &request.Port) != nil || request.Port < 1 || request.Port > 65535 {
			return nil, errors.New("node_listener_port_required")
		}
		requests = append(requests, request)
	}
	return requests, nil
}

func loadListenerRequests(db *gorm.DB, node model.Node) ([]listenerRequest, error) {
	spec, err := liveVersion(db, node)
	if err != nil {
		return nil, err
	}
	var rows []model.NodeOverride
	if err := db.Where("node_id = ? AND path IN ? AND archived = false", node.Id, []string{"/listen_port", "/transport", "/transport/type", "/network"}).Find(&rows).Error; err != nil {
		return nil, err
	}
	overrides := map[string][]SpecOverride{}
	for _, row := range rows {
		var source ValueSource
		if row.Operation == "set" {
			if err := json.Unmarshal(row.Source, &source); err != nil {
				return nil, err
			}
		}
		overrides[row.ConnectionKey] = append(overrides[row.ConnectionKey], SpecOverride{Path: row.Path, Operation: row.Operation, Source: source})
	}
	return listenerRequests(db, node, spec, overrides)
}

func reserveListenerPort(tx *gorm.DB, nodeID uint, host, key string, endpoint listenerSocket) error {
	query := tx.Where("host = ? AND network = ? AND port = ?", host, endpoint.Network, endpoint.Port)
	var existing model.NodePortReservation
	result := query.First(&existing)
	if result.Error == nil {
		if existing.NodeId == nodeID && existing.ConnectionKey == key {
			return nil
		}
		return errListenerReserved
	}
	if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return result.Error
	}
	row := model.NodePortReservation{NodeId: nodeID, ConnectionKey: key, Host: host, Network: endpoint.Network, Port: endpoint.Port}
	result = tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "host"}, {Name: "network"}, {Name: "port"}},
		DoNothing: true,
	}).Create(&row)
	if result.Error != nil || result.RowsAffected != 0 {
		return result.Error
	}
	if err := query.First(&existing).Error; err != nil {
		return err
	}
	if existing.NodeId != nodeID || existing.ConnectionKey != key {
		return errListenerReserved
	}
	return nil
}

func reserveListenerPlan(tx *gorm.DB, nodeID uint, host string, requests []listenerRequest, occupied map[listenerSocket]bool) ([]provisionListener, error) {
	if host == "" && len(requests) > 0 {
		return nil, errors.New("node_physical_host_required")
	}
	reserved := make(map[string][]provisionListener, len(requests))
	reserve := func(request listenerRequest) error {
		sockets := expandSocket(request.listenerSocket)
		for _, socket := range sockets {
			if occupied[socket] {
				return errListenerOccupied
			}
		}
		write := func(db *gorm.DB) error {
			for _, socket := range sockets {
				if err := reserveListenerPort(db, nodeID, host, request.Key, socket); err != nil {
					return err
				}
			}
			return nil
		}
		var err error
		if len(sockets) > 1 {
			err = tx.Transaction(write)
		} else {
			err = write(tx)
		}
		if err != nil {
			return err
		}
		for _, socket := range sockets {
			reserved[request.Key] = append(reserved[request.Key], provisionListener{request.Key, socket.Network, socket.Port})
		}
		return nil
	}
	for _, request := range requests {
		if request.Port != 0 {
			if err := reserve(request); err != nil {
				return nil, err
			}
		}
	}
	for _, request := range requests {
		if request.Port != 0 {
			continue
		}
		allocated := false
		for _, port := range automaticListenerPorts {
			request.Port = port
			if err := reserve(request); err != nil {
				if errors.Is(err, errListenerReserved) || errors.Is(err, errListenerOccupied) {
					continue
				}
				return nil, err
			}
			if err := storeGeneratedValue(tx, nodeID, request.Key, "listen_port", json.RawMessage(strconv.Itoa(port))); err != nil {
				return nil, err
			}
			allocated = true
			break
		}
		if !allocated {
			return nil, errAutoPortsExhausted
		}
	}
	listeners := make([]provisionListener, 0, len(requests))
	for _, request := range requests {
		listeners = append(listeners, reserved[request.Key]...)
	}
	return listeners, nil
}

func listenerProbes(requests []listenerRequest) []listenerSocket {
	probes := make([]listenerSocket, 0, len(requests))
	seen := map[listenerSocket]bool{}
	add := func(endpoint listenerSocket) {
		for _, socket := range expandSocket(endpoint) {
			if !seen[socket] {
				probes = append(probes, socket)
				seen[socket] = true
			}
		}
	}
	for _, request := range requests {
		if request.Port != 0 {
			add(request.listenerSocket)
			continue
		}
		for _, port := range automaticListenerPorts {
			add(listenerSocket{Network: request.Network, Port: port})
		}
	}
	return probes
}

type listenerInspection struct {
	Arch        string           `json:"arch"`
	ControlPort int              `json:"control_port"`
	Occupied    []listenerSocket `json:"occupied"`
	Error       string           `json:"error"`
}

func inspectListenerSockets(ctx context.Context, client *ssh.Client, install model.NodeInstallation, requests []listenerRequest) (listenerInspection, map[listenerSocket]bool, error) {
	var inspection listenerInspection
	var fixedTCP []int
	for _, request := range requests {
		if (request.Network == "tcp" || request.Network == "both") && request.Port != 0 {
			fixedTCP = append(fixedTCP, request.Port)
		}
	}
	output, err := remotePython(ctx, client, install.SSHUser, liveInspectionScript, map[string]interface{}{
		"id": install.NodeId, "owner": install.OwnerID, "control_port": install.ControlPort,
		"probes": listenerProbes(requests), "fixed_tcp_ports": fixedTCP,
	})
	if err != nil {
		return inspection, nil, errPortInspection
	}
	if json.Unmarshal(output, &inspection) != nil {
		return inspection, nil, errPortInspection
	}
	if inspection.Error == errListenerOccupied.Error() {
		return inspection, nil, errListenerOccupied
	}
	if inspection.Error != "" || inspection.ControlPort == 0 {
		return inspection, nil, errPortInspection
	}
	occupied := map[listenerSocket]bool{{Network: "tcp", Port: inspection.ControlPort}: true}
	for _, endpoint := range inspection.Occupied {
		occupied[endpoint] = true
	}
	return inspection, occupied, nil
}

// Applied listeners need no new SSH probe on every reconcile. A new automatic
// request or any changed fixed listener must be checked on its actual host.
func changedListeners(node model.Node, requests []listenerRequest) []listenerRequest {
	var snapshot Snapshot
	_ = json.Unmarshal(node.AppliedSnapshot, &snapshot)
	applied := map[string]listenerSocket{}
	for _, inbound := range snapshot.Inbounds {
		var options struct {
			Port      int               `json:"listen_port"`
			Transport listenerTransport `json:"transport"`
			Network   string            `json:"network"`
		}
		if json.Unmarshal(inbound.Options, &options) == nil {
			applied[inbound.ConnectionKey] = listenerSocket{Network: listenerNetwork(inbound.Type, options.Transport, options.Network), Port: options.Port}
		}
	}
	var changes []listenerRequest
	for _, request := range requests {
		if request.Port == 0 || applied[request.Key] != request.listenerSocket {
			changes = append(changes, request)
		}
	}
	return changes
}

func sameListenerDraft(before, current model.Node) bool {
	return current.Enable == before.Enable && current.TemplateId == before.TemplateId &&
		current.TemplateTargetVersion == before.TemplateTargetVersion &&
		current.SettingsVersion == before.SettingsVersion &&
		current.ManagementGeneration == before.ManagementGeneration &&
		current.Address == before.Address
}

func inspectChangedListeners(ctx context.Context, db *gorm.DB, node model.Node) (map[listenerSocket]bool, error) {
	if !node.Enable || node.TemplateTargetVersion == 0 {
		return nil, nil
	}
	var install model.NodeInstallation
	if err := db.First(&install, "node_id = ?", node.Id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if install.OwnerID == "" || install.PrivateKey == "" {
		return nil, nil
	}
	requests, err := loadListenerRequests(db, node)
	if err != nil {
		return nil, err
	}
	changed := changedListeners(node, requests)
	if len(changed) == 0 {
		return nil, nil
	}
	probeContext, cancel := context.WithTimeout(ctx, portInspectionTimeout)
	defer cancel()
	client, err := connectSSH(probeContext, &install, "", false)
	if err != nil {
		return nil, errPortInspection
	}
	defer client.Close()
	_, occupied, err := inspectListenerSockets(probeContext, client, install, changed)
	return occupied, err
}

func listenerFailureCode(failure error) string {
	for _, code := range []error{errListenerOccupied, errListenerReserved, errAutoPortsExhausted, errPortInspection, errRealityHandshakeLoop, errNodeDetour} {
		if errors.Is(failure, code) {
			return code.Error()
		}
	}
	return "structural_update_failed"
}
