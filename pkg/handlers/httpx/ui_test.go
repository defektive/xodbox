package httpx

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func uiHandler(t *testing.T, cfg map[string]string) *Handler {
	t.Helper()
	h := NewHandler(cfg).(*Handler)
	return h
}

func TestUIMountServesSPAWithInjectedBase(t *testing.T) {
	h := uiHandler(t, map[string]string{"listener": ":0", "ui_path": "admin"})
	if h.UIPath != "/admin/" {
		t.Fatalf("UIPath = %q, want /admin/", h.UIPath)
	}
	mux := h.serverMux()

	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/ = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `window.__XODBOX_BASE__ = "/admin/"`) {
		t.Errorf("index.html did not have base injected:\n%s", body[:min(len(body), 300)])
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if csp := rr.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("missing Content-Security-Policy on admin UI")
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options: DENY")
	}
}

func TestUISPAFallbackForClientRoutes(t *testing.T) {
	h := uiHandler(t, map[string]string{"listener": ":0", "ui_path": "admin"})
	mux := h.serverMux()

	// A client-side route with no matching asset should fall back to index.html.
	req := httptest.NewRequest(http.MethodGet, "/admin/requests", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/requests = %d, want 200 (SPA fallback)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `id="root"`) {
		t.Error("SPA fallback should serve index.html")
	}
}

func TestUICIDRAllowlist(t *testing.T) {
	h := uiHandler(t, map[string]string{
		"listener":       ":0",
		"ui_path":        "admin",
		"ui_allow_cidrs": "10.0.0.0/8, 192.168.1.5",
	})
	if len(h.UIAllowCIDRs) != 2 {
		t.Fatalf("parsed %d CIDRs, want 2", len(h.UIAllowCIDRs))
	}
	mux := h.serverMux()

	cases := []struct {
		remote string
		want   int
	}{
		{"10.1.2.3:5000", http.StatusOK},          // inside 10/8
		{"192.168.1.5:5000", http.StatusOK},       // exact /32
		{"192.168.1.6:5000", http.StatusNotFound}, // outside
		{"8.8.8.8:5000", http.StatusNotFound},     // public, denied
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
		req.RemoteAddr = tc.remote
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Errorf("remote %s => %d, want %d", tc.remote, rr.Code, tc.want)
		}
	}
}

func TestUIDisabledByDefault(t *testing.T) {
	h := uiHandler(t, map[string]string{"listener": ":0"})
	if h.UIPath != "" {
		t.Errorf("UIPath = %q, want empty (disabled by default)", h.UIPath)
	}
}

func TestParseCIDRs(t *testing.T) {
	nets, bad := parseCIDRs("10.0.0.0/8, 127.0.0.1 , , 2001:db8::/32, garbage")
	if len(nets) != 3 {
		t.Errorf("parsed %d nets, want 3", len(nets))
	}
	if len(bad) != 1 || bad[0] != "garbage" {
		t.Errorf("bad entries = %v, want [garbage]", bad)
	}
}

func TestIPAllowed(t *testing.T) {
	_, n, _ := net.ParseCIDR("10.0.0.0/8")
	nets := []*net.IPNet{n}
	if !ipAllowed(nets, "10.9.8.7:1234") {
		t.Error("10.9.8.7 should be allowed")
	}
	if ipAllowed(nets, "11.0.0.1:1234") {
		t.Error("11.0.0.1 should be denied")
	}
	if ipAllowed(nets, "not-an-ip") {
		t.Error("unparseable remote should be denied")
	}
}
