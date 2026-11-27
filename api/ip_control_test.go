package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alireza0/s-ui/antiabuse/engine"
	ipcontrol "github.com/alireza0/s-ui/antiabuse/panel"
	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/database"
)

func registerTestIPControl(t *testing.T) *ipcontrol.Controller {
	t.Helper()
	runtime, err := ipruntime.New(engine.DefaultProfile(), nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ipcontrol.NewController(ipcontrol.NewStore(database.GetDB()), runtime, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ipcontrol.Register(c)
	t.Cleanup(func() { ipcontrol.Unregister(c) })
	return c
}

func TestIPControlRoutesRequireExistingAuthentication(t *testing.T) {
	server := loginEngine(t)
	registerTestIPControl(t)
	for _, path := range []string{"settings", "groups", "clients?ids=1", "events"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/antiabuse/"+path, nil)
		request.Header.Set("X-Requested-With", "XMLHttpRequest")
		server.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatal("IP control bypassed session authentication")
		}
		response = httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/apiv2/antiabuse/"+path, nil))
		if !strings.Contains(response.Body.String(), "invalid token") {
			t.Fatal("IP control bypassed token authentication")
		}
	}
}

func TestIPControlTokenAPIValidatesAndSavesConfiguration(t *testing.T) {
	srv, token := apiv2TestServer(t)
	c := registerTestIPControl(t)
	call := func(method, path, body string) Msg {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+"/apiv2/antiabuse/"+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Token", token)
		response, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result Msg
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	if !call("GET", "settings", "").Success {
		t.Fatal("configuration unavailable through authenticated API")
	}
	for _, path := range []string{"clients?ids=0", "clients?ids=1,bad", "events?limit=0", "events?before=bad"} {
		if call("GET", path, "").Success {
			t.Fatal("invalid query accepted")
		}
	}
	value, err := c.Configuration()
	if err != nil {
		t.Fatal(err)
	}
	value.Enabled = true
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !call("PUT", "settings", string(body)).Success {
		t.Fatal("valid settings rejected")
	}
	if call("PUT", "settings", string(body)).Success {
		t.Fatal("stale form overwrote current settings")
	}
	if call("PUT", "settings", `{"unknown":true}`).Success {
		t.Fatal("unknown setting accepted")
	}
	if !call("GET", "clients?ids=1,2", "").Success {
		t.Fatal("readonly client status unavailable")
	}
}
