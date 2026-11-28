package nodeagent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	ipagent "github.com/alireza0/s-ui/antiabuse/agent"
	"github.com/alireza0/s-ui/antiabuse/engine"
	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/antiabuse/wire"
)

func TestIPControlHTTPRequiresFreshIdentityAndStrictMessages(t *testing.T) {
	runtime, err := ipruntime.New(engine.DefaultProfile(), nil)
	if err != nil {
		t.Fatal(err)
	}
	session := ipagent.New(runtime, nil)
	id := wire.Identity{NodeID: 1, Epoch: "epoch", AccessRevision: 1}
	session.SetIdentity(id)
	call := func(method, path string, value any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		ipControlRequest(session, response, httptest.NewRequest(method, path, bytes.NewReader(body)))
		return response
	}
	page := func() wire.Page {
		t.Helper()
		response := call(http.MethodGet, wire.StatePath+"?node_id=1&epoch=epoch&access_revision=1", nil)
		if response.Code != http.StatusOK {
			t.Fatal("current observation unavailable")
		}
		var result wire.Page
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	initial := page()
	config := wire.Configuration{Version: wire.Version, Identity: id, Scope: "scope", Revision: 1,
		Boot: initial.Boot, Challenge: initial.Challenge, Enabled: true,
		Profile: wire.Profile{ActivitySeconds: 60, TransitionSeconds: 120, ConfirmationSeconds: 30}}
	if call(http.MethodPost, wire.ConfigPath, config).Code != http.StatusMethodNotAllowed {
		t.Fatal("wrong method accepted")
	}
	if call(http.MethodPut, wire.ConfigPath, config).Code != http.StatusOK {
		t.Fatal("fresh configuration rejected")
	}
	if call(http.MethodPut, wire.ConfigPath, config).Code != http.StatusConflict {
		t.Fatal("configuration replay accepted")
	}
	if call(http.MethodPut, wire.ConfigPath, map[string]bool{"unknown": true}).Code != http.StatusUnprocessableEntity {
		t.Fatal("unknown fields accepted")
	}
	if call(http.MethodGet, wire.StatePath+"?node_id=1&epoch=other&access_revision=1", nil).Code != http.StatusConflict {
		t.Fatal("foreign access identity accepted")
	}
	current := page()
	config.Revision, config.Enabled, config.Boot, config.Challenge = 2, false, current.Boot, current.Challenge
	if call(http.MethodPut, wire.ConfigPath, config).Code != http.StatusOK {
		t.Fatal("disable rejected")
	}
	if report := runtime.Report("node:1"); len(report.Snapshot.Entries) != 0 {
		t.Fatal("disabled agent still reports IP activity")
	}
}
