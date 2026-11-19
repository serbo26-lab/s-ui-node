package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/nodes"
	"github.com/gin-gonic/gin"
)

func modelAPIContext(method, path, body string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, path, strings.NewReader(body))
	if method == "POST" {
		c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return c, w
}

func TestNodeModelReadOnlyAPIAndPreparedState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	if err := database.InitDB(filepath.Join(t.TempDir(), "api.db")); err != nil {
		t.Fatal(err)
	}
	db := database.GetDB()
	sql, _ := db.DB()
	t.Cleanup(func() { sql.Close() })
	if err := db.Create(&model.Node{Id: 1, Name: "test", Enable: true, ControlKey: "fixture-server-secret"}).Error; err != nil {
		t.Fatal(err)
	}
	a := &ApiService{}
	c, w := modelAPIContext("GET", "/api/node-migration?id=1", "")
	a.GetNodeMigration(c)
	var response struct {
		Success bool                  `json:"success"`
		Obj     nodes.MigrationReport `json:"obj"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Success || response.Obj.Digest == "" || strings.Contains(w.Body.String(), "fixture-server-secret") {
		t.Fatal("report failed or exposed private node data")
	}
	var count int64
	db.Model(&model.ClientNode{}).Count(&count)
	if count != 0 {
		t.Fatal("GET changed grants")
	}
	request, _ := json.Marshal(nodes.PrepareMigrationRequest{NodeId: 1, ReportDigest: response.Obj.Digest})
	c, w = modelAPIContext("POST", "/api/node-migration", url.Values{"data": []string{string(request)}}.Encode())
	a.PrepareNodeMigration(c, "test")
	if !strings.Contains(w.Body.String(), `"state":"prepared"`) || strings.Contains(w.Body.String(), "decisions") {
		t.Fatal("prepare activated access or exposed private decisions")
	}
	c, w = modelAPIContext("GET", "/api/node-migration?id=-1", "")
	a.GetNodeMigration(c)
	if strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatal("invalid ID accepted")
	}
	c, w = modelAPIContext("GET", "/api/node-template-history?id=invalid", "")
	a.GetNodeTemplateHistory(c)
	if strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatal("invalid template ID accepted")
	}
}
