package httpx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defektive/xodbox/pkg/model"
)

const testPassword = "correct horse battery staple"

// testSeq makes test-created names unique across tests and across -count reruns
// (the model DB is a shared, persistent singleton, so t.Name() alone collides
// on the second run).
var testSeq atomic.Int64

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, testSeq.Add(1))
}

// adminTestServer starts the admin surface (API + SPA) at base "/" with a
// cookie-jar client, and creates a user to log in as.
func adminTestServer(t *testing.T) (*httptest.Server, *http.Client, *model.User) {
	t.Helper()
	u, err := model.CreateUser(uniqueName("admin"), testPassword, model.RoleAdmin)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	handler, err := (&Handler{}).adminHandler("/")
	if err != nil {
		t.Fatalf("adminHandler: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return srv, &http.Client{Jar: jar}, u
}

// getCSRF fetches a CSRF token (and sets the csrf cookie in the jar).
func getCSRF(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	resp, err := c.Get(base + "/api/csrf")
	if err != nil {
		t.Fatalf("GET /api/csrf: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		CSRFToken string `json:"csrfToken"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.CSRFToken == "" {
		t.Fatal("empty csrf token")
	}
	return body.CSRFToken
}

func postJSON(t *testing.T, c *http.Client, url, csrf string, v any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(v)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set(csrfHeader, csrf)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

func TestLoginFlow(t *testing.T) {
	srv, c, u := adminTestServer(t)
	csrf := getCSRF(t, c, srv.URL)

	resp := postJSON(t, c, srv.URL+"/api/login", csrf, loginRequest{Username: u.Username, Password: testPassword})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Session cookie now lets /api/me resolve the user.
	meResp, _ := c.Get(srv.URL + "/api/me")
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("/api/me = %d, want 200", meResp.StatusCode)
	}
	var me userView
	_ = json.NewDecoder(meResp.Body).Decode(&me)
	meResp.Body.Close()
	if me.Username != u.Username || me.Role != model.RoleAdmin {
		t.Errorf("/api/me = %+v", me)
	}

	// Logout revokes the session.
	out := postJSON(t, c, srv.URL+"/api/logout", csrf, nil)
	if out.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", out.StatusCode)
	}
	out.Body.Close()

	after, _ := c.Get(srv.URL + "/api/me")
	if after.StatusCode != http.StatusUnauthorized {
		t.Errorf("/api/me after logout = %d, want 401", after.StatusCode)
	}
	after.Body.Close()
}

func TestLoginBadCredentials(t *testing.T) {
	srv, c, u := adminTestServer(t)
	csrf := getCSRF(t, c, srv.URL)
	resp := postJSON(t, c, srv.URL+"/api/login", csrf, loginRequest{Username: u.Username, Password: "wrong password entirely"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("login(bad) = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestLoginRequiresCSRF(t *testing.T) {
	srv, c, u := adminTestServer(t)
	getCSRF(t, c, srv.URL) // sets the cookie but we omit the header
	resp := postJSON(t, c, srv.URL+"/api/login", "", loginRequest{Username: u.Username, Password: testPassword})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("login without csrf header = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestLoginRateLimited(t *testing.T) {
	srv, c, _ := adminTestServer(t)
	// The limiter counts every attempt; the 11th within the window is blocked.
	var last int
	for i := 0; i < 11; i++ {
		resp := postJSON(t, c, srv.URL+"/api/login", "", loginRequest{Username: "x", Password: "y"})
		last = resp.StatusCode
		resp.Body.Close()
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("11th login attempt = %d, want 429", last)
	}
}

func TestBearerAPIKeyAuth(t *testing.T) {
	srv, _, u := adminTestServer(t)
	full, _, err := model.NewAPIKey(u.ID, "test", nil)
	if err != nil {
		t.Fatal(err)
	}

	// A bearer key authenticates with no cookie/CSRF.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+full)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bearer /api/me = %d, want 200", resp.StatusCode)
	}
	var me userView
	_ = json.NewDecoder(resp.Body).Decode(&me)
	if me.Username != u.Username {
		t.Errorf("bearer identity = %q, want %q", me.Username, u.Username)
	}

	// A bogus key is rejected.
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/me", nil)
	req2.Header.Set("Authorization", "Bearer xdbx_not-a-real-key")
	r2, _ := (&http.Client{}).Do(req2)
	if r2.StatusCode != http.StatusUnauthorized {
		t.Errorf("bogus bearer = %d, want 401", r2.StatusCode)
	}
	r2.Body.Close()
}

func TestUnauthenticatedRejected(t *testing.T) {
	srv, _, _ := adminTestServer(t)
	resp, _ := http.Get(srv.URL + "/api/me")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/api/me anon = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAdminHandlerServesSPAOutsideAPI(t *testing.T) {
	handler, _ := (&Handler{}).adminHandler("/")
	srv := httptest.NewServer(handler)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `id="root"`) {
		t.Errorf("non-API path should serve the SPA; code=%d", resp.StatusCode)
	}
}
