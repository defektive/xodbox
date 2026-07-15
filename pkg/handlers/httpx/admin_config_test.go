package httpx

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
	"gopkg.in/yaml.v3"
)

// testConfigOps is a simple types.ConfigOps backed by a temp file.
type testConfigOps struct {
	path string
}

func newTestConfigOps(t *testing.T, initial *types.ConfigFile) *testConfigOps {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "test.yaml")
	if initial != nil {
		b, _ := yaml.Marshal(initial)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := os.WriteFile(p, []byte("defaults: {}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &testConfigOps{path: p}
}

func (o *testConfigOps) FilePath() string { return o.path }
func (o *testConfigOps) Read() (*types.ConfigFile, error) {
	b, err := os.ReadFile(o.path)
	if err != nil {
		return nil, err
	}
	cf := &types.ConfigFile{}
	err = yaml.Unmarshal(b, cf)
	return cf, err
}
func (o *testConfigOps) Write(cf *types.ConfigFile) error {
	b, err := yaml.Marshal(cf)
	if err != nil {
		return err
	}
	return os.WriteFile(o.path, b, 0o644)
}
func (o *testConfigOps) Validate(cf *types.ConfigFile) []string {
	valid := map[string]bool{"TCP": true, "DNS": true, "HTTPX": true, "SSH": true, "SMTP": true, "FTP": true, "SMB": true}
	validN := map[string]bool{"app_log": true, "discord": true, "slack": true, "webhook": true}
	validW := map[string]bool{"purge": true}
	var errs []string
	for i, h := range cf.Handlers {
		if h["handler"] == "" || !valid[h["handler"]] {
			errs = append(errs, "handlers["+itoa(i)+"]: invalid")
		}
	}
	for i, n := range cf.Notifiers {
		if n["notifier"] == "" || !validN[n["notifier"]] {
			errs = append(errs, "notifiers["+itoa(i)+"]: invalid")
		}
	}
	for i, w := range cf.Workers {
		if w["worker"] == "" || !validW[w["worker"]] {
			errs = append(errs, "workers["+itoa(i)+"]: invalid")
		}
	}
	return errs
}
func (o *testConfigOps) HandlerNames() []string {
	return []string{"DNS", "FTP", "HTTPX", "SMB", "SMTP", "SSH", "TCP"}
}
func (o *testConfigOps) NotifierNames() []string {
	return []string{"app_log", "discord", "slack", "webhook"}
}
func (o *testConfigOps) WorkerNames() []string { return []string{"purge"} }

func itoa(i int) string { return string(rune('0' + i)) }

func configTestServer(t *testing.T, ops types.ConfigOps) (*httptest.Server, *http.Client, *model.User) {
	t.Helper()
	u, err := model.CreateUser(uniqueName("cfgadmin"), testPassword, model.RoleAdmin)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	handler, err := (&Handler{ConfigOps: ops}).adminHandler("/")
	if err != nil {
		t.Fatalf("adminHandler: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return srv, &http.Client{Jar: jar}, u
}

func loginClient(t *testing.T, c *http.Client, base string, u *model.User) string {
	t.Helper()
	csrf := getCSRF(t, c, base)
	resp := postJSON(t, c, base+"/api/login", csrf, loginRequest{Username: u.Username, Password: testPassword})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
	return csrf
}

func putJSON(t *testing.T, c *http.Client, url, csrf string, v any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(v)
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set(csrfHeader, csrf)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", url, err)
	}
	return resp
}

func TestConfigRequiresAdmin(t *testing.T) {
	ops := newTestConfigOps(t, nil)
	srv, c, _ := configTestServer(t, ops)
	regular, err := model.CreateUser(uniqueName("cfguser"), testPassword, model.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	csrf := loginClient(t, c, srv.URL, regular)

	resp, _ := c.Get(srv.URL + "/api/config")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("GET /api/config as user = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	resp = putJSON(t, c, srv.URL+"/api/config", csrf, configPutRequest{})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("PUT /api/config as user = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestGetConfig(t *testing.T) {
	ops := newTestConfigOps(t, &types.ConfigFile{
		Defaults:  map[string]string{"server_name": "TestBot"},
		Handlers:  []map[string]string{{"handler": "TCP", "listener": ":0"}},
		Notifiers: []map[string]string{{"notifier": "app_log"}},
	})
	srv, c, u := configTestServer(t, ops)
	loginClient(t, c, srv.URL, u)

	resp, _ := c.Get(srv.URL + "/api/config")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/config = %d, want 200", resp.StatusCode)
	}
	var body configResponse
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()

	if body.ConfigPath != ops.path {
		t.Errorf("configPath = %q, want %q", body.ConfigPath, ops.path)
	}
	if body.Defaults["server_name"] != "TestBot" {
		t.Errorf("server_name = %q, want TestBot", body.Defaults["server_name"])
	}
	if len(body.Handlers) != 1 || body.Handlers[0]["handler"] != "TCP" {
		t.Errorf("handlers = %v", body.Handlers)
	}
}

func TestPutConfigValid(t *testing.T) {
	ops := newTestConfigOps(t, nil)
	srv, c, u := configTestServer(t, ops)
	csrf := loginClient(t, c, srv.URL, u)

	req := configPutRequest{
		Defaults:  map[string]string{"server_name": "Updated"},
		Handlers:  []map[string]string{{"handler": "TCP", "listener": ":1234"}},
		Notifiers: []map[string]string{{"notifier": "app_log"}},
	}
	resp := putJSON(t, c, srv.URL+"/api/config", csrf, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/config = %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()

	if body["saved"] != true {
		t.Errorf("saved = %v, want true", body["saved"])
	}

	cf, err := ops.Read()
	if err != nil {
		t.Fatal(err)
	}
	if cf.Defaults["server_name"] != "Updated" {
		t.Errorf("server_name on disk = %q, want Updated", cf.Defaults["server_name"])
	}
}

func TestPutConfigInvalidHandler(t *testing.T) {
	ops := newTestConfigOps(t, nil)
	srv, c, u := configTestServer(t, ops)
	csrf := loginClient(t, c, srv.URL, u)

	req := configPutRequest{
		Handlers: []map[string]string{{"handler": "NOPE"}},
	}
	resp := putJSON(t, c, srv.URL+"/api/config", csrf, req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT invalid config = %d, want 400", resp.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()

	errs, ok := body["errors"].([]any)
	if !ok || len(errs) == 0 {
		t.Errorf("expected validation errors, got %v", body)
	}
}

func TestGetConfigSchema(t *testing.T) {
	ops := newTestConfigOps(t, nil)
	srv, c, u := configTestServer(t, ops)
	loginClient(t, c, srv.URL, u)

	resp, _ := c.Get(srv.URL + "/api/config/schema")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/config/schema = %d, want 200", resp.StatusCode)
	}
	var body configSchemaResponse
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()

	if len(body.Handlers) != 7 {
		t.Errorf("handlers count = %d, want 7", len(body.Handlers))
	}
	if len(body.Notifiers) != 4 {
		t.Errorf("notifiers count = %d, want 4", len(body.Notifiers))
	}
	if len(body.Workers) != 1 {
		t.Errorf("workers count = %d, want 1", len(body.Workers))
	}
}
