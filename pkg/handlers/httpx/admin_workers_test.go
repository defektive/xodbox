package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
)

// workerApp is a types.App whose worker methods are scriptable, so the handler
// can be tested against each outcome the engine can produce.
type workerApp struct {
	statuses  []types.WorkerStatus
	triggered []string
	triggerFn func(string) error
}

func (a *workerApp) Run()                                       {}
func (a *workerApp) RegisterNotificationHandler(types.Notifier) {}
func (a *workerApp) GetTemplateData() map[string]string         { return map[string]string{} }
func (a *workerApp) Reload() error                              { return nil }
func (a *workerApp) WorkerStatus() []types.WorkerStatus         { return a.statuses }
func (a *workerApp) TriggerWorker(name string) error {
	a.triggered = append(a.triggered, name)
	if a.triggerFn != nil {
		return a.triggerFn(name)
	}
	return nil
}

func workersTestServer(t *testing.T, app types.App) (*httptest.Server, *http.Client, *model.User) {
	t.Helper()
	u, err := model.CreateUser(uniqueName("jobsadmin"), testPassword, model.RoleAdmin)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	handler, err := (&Handler{app: app}).adminHandler("/")
	if err != nil {
		t.Fatalf("adminHandler: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return srv, &http.Client{Jar: jar}, u
}

func TestGetWorkersReturnsStatus(t *testing.T) {
	last := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	app := &workerApp{statuses: []types.WorkerStatus{{
		Name:           "purge",
		Schedule:       "@daily",
		LastRun:        &last,
		LastDurationMS: 1500,
	}}}
	srv, c, u := workersTestServer(t, app)
	loginClient(t, c, srv.URL, u)

	resp, err := c.Get(srv.URL + "/api/workers")
	if err != nil {
		t.Fatalf("GET /api/workers: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body struct {
		Workers []types.WorkerStatus `json:"workers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Workers) != 1 || body.Workers[0].Name != "purge" {
		t.Fatalf("workers = %+v, want one named purge", body.Workers)
	}
	if body.Workers[0].LastDurationMS != 1500 {
		t.Errorf("LastDurationMS = %d, want 1500", body.Workers[0].LastDurationMS)
	}
}

func TestRunWorkerAccepted(t *testing.T) {
	app := &workerApp{}
	srv, c, u := workersTestServer(t, app)
	csrf := loginClient(t, c, srv.URL, u)

	resp := postJSON(t, c, srv.URL+"/api/workers/purge/run", csrf, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	if len(app.triggered) != 1 || app.triggered[0] != "purge" {
		t.Errorf("triggered = %v, want [purge]", app.triggered)
	}
}

func TestRunUnknownWorkerIs404(t *testing.T) {
	app := &workerApp{triggerFn: func(string) error { return types.ErrUnknownWorker }}
	srv, c, u := workersTestServer(t, app)
	csrf := loginClient(t, c, srv.URL, u)

	resp := postJSON(t, c, srv.URL+"/api/workers/nope/run", csrf, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// A second run request while one is in flight must be refused, not queued.
func TestRunBusyWorkerIs409(t *testing.T) {
	app := &workerApp{triggerFn: func(string) error { return types.ErrWorkerBusy }}
	srv, c, u := workersTestServer(t, app)
	csrf := loginClient(t, c, srv.URL, u)

	resp := postJSON(t, c, srv.URL+"/api/workers/purge/run", csrf, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

// Running a job deletes data permanently, so a non-admin must not be able to.
func TestWorkerEndpointsRequireAdmin(t *testing.T) {
	app := &workerApp{}
	handler, err := (&Handler{app: app}).adminHandler("/")
	if err != nil {
		t.Fatalf("adminHandler: %v", err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	u, err := model.CreateUser(uniqueName("jobsuser"), testPassword, model.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	csrf := loginClient(t, c, srv.URL, u)

	resp, err := c.Get(srv.URL + "/api/workers")
	if err != nil {
		t.Fatalf("GET /api/workers: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("GET status = %d, want 403", resp.StatusCode)
	}

	runResp := postJSON(t, c, srv.URL+"/api/workers/purge/run", csrf, nil)
	runResp.Body.Close()
	if runResp.StatusCode != http.StatusForbidden {
		t.Errorf("POST status = %d, want 403", runResp.StatusCode)
	}
	if len(app.triggered) != 0 {
		t.Errorf("a non-admin managed to trigger %v", app.triggered)
	}
}

// The endpoints are wired to the running App; without one they report
// unavailable rather than panicking.
func TestWorkerEndpointsWithoutApp(t *testing.T) {
	handler, err := (&Handler{}).adminHandler("/")
	if err != nil {
		t.Fatalf("adminHandler: %v", err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	u, err := model.CreateUser(uniqueName("jobsnoapp"), testPassword, model.RoleAdmin)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	loginClient(t, c, srv.URL, u)

	resp, err := c.Get(srv.URL + "/api/workers")
	if err != nil {
		t.Fatalf("GET /api/workers: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}
