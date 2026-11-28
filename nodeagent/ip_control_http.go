package nodeagent

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	ipagent "github.com/alireza0/s-ui/antiabuse/agent"
	"github.com/alireza0/s-ui/antiabuse/wire"
)

func registerIPControl(mux *http.ServeMux, manager *ManagerV2) {
	for _, path := range []string{wire.ConfigPath, wire.StatePath, wire.DecisionPath} {
		mux.HandleFunc(path, func(writer http.ResponseWriter, request *http.Request) {
			runtime, ok := manager.runtime.(ipControlRuntime)
			if !ok || runtime.IPControlSession() == nil {
				http.Error(writer, "IP control unavailable", http.StatusNotImplemented)
				return
			}
			if !manager.ipControlReady() {
				http.Error(writer, "access synchronization pending", http.StatusServiceUnavailable)
				return
			}
			ipControlRequest(runtime.IPControlSession(), writer, request)
		})
	}
}

func ipControlRequest(session *ipagent.Session, writer http.ResponseWriter, request *http.Request) {
	var value any
	var err error
	switch request.URL.Path {
	case wire.StatePath:
		if request.Method != http.MethodGet {
			http.Error(writer, methodNotAllowed, http.StatusMethodNotAllowed)
			return
		}
		value, err = readIPControlPage(session, request)
	case wire.ConfigPath, wire.DecisionPath:
		if request.Method != http.MethodPut {
			http.Error(writer, methodNotAllowed, http.StatusMethodNotAllowed)
			return
		}
		err = writeIPControl(session, writer, request)
		value = struct {
			Applied bool `json:"applied"`
		}{Applied: err == nil}
	}
	if err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, ipagent.ErrConflict) {
			status = http.StatusConflict
		}
		http.Error(writer, "IP control request not applied", status)
		return
	}
	writer.Header().Set(contentTypeHeader, jsonContentType)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeIPControl(session *ipagent.Session, writer http.ResponseWriter, request *http.Request) error {
	request.Body = http.MaxBytesReader(writer, request.Body, 8<<20)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if request.URL.Path == wire.ConfigPath {
		var value wire.Configuration
		if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
			return wire.ErrInvalid
		}
		return session.Configure(value)
	}
	var value wire.Decision
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
		return wire.ErrInvalid
	}
	return session.Apply(value)
}

func readIPControlPage(session *ipagent.Session, request *http.Request) (wire.Page, error) {
	query := request.URL.Query()
	nodeID, err := strconv.ParseUint(query.Get("node_id"), 10, 64)
	if err != nil {
		return wire.Page{}, wire.ErrInvalid
	}
	access, err := strconv.ParseUint(query.Get("access_revision"), 10, 64)
	if err != nil {
		return wire.Page{}, wire.ErrInvalid
	}
	sequence, offset := uint64(0), 0
	if query.Has("sequence") {
		sequence, err = strconv.ParseUint(query.Get("sequence"), 10, 64)
		if err != nil {
			return wire.Page{}, wire.ErrInvalid
		}
	}
	if query.Has("offset") {
		offset, err = strconv.Atoi(query.Get("offset"))
		if err != nil {
			return wire.Page{}, wire.ErrInvalid
		}
	}
	return session.State(wire.Identity{NodeID: nodeID, Epoch: query.Get("epoch"), AccessRevision: access}, query.Get("boot"), sequence, offset)
}
