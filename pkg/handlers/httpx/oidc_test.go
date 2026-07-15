package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/defektive/xodbox/pkg/model"
)

func TestNewOIDCAuthDisabledWithoutIssuer(t *testing.T) {
	if newOIDCAuth(map[string]string{"oidc_client_id": "abc"}) != nil {
		t.Error("OIDC must be disabled without an issuer")
	}
	if newOIDCAuth(map[string]string{"oidc_issuer": "https://idp"}) != nil {
		t.Error("OIDC must be disabled without a client_id")
	}
	if newOIDCAuth(map[string]string{}) != nil {
		t.Error("OIDC must be disabled with empty config")
	}
}

func TestNewOIDCAuthDefaults(t *testing.T) {
	o := newOIDCAuth(map[string]string{
		"oidc_issuer":    "https://idp.example",
		"oidc_client_id": "client-123",
	})
	if o == nil {
		t.Fatal("expected OIDC enabled")
	}
	if o.cfg.DefaultRole != model.RoleUser {
		t.Errorf("default role = %q, want user", o.cfg.DefaultRole)
	}
	if o.cfg.GroupsClaim != defaultGroupsClaim {
		t.Errorf("groups claim = %q, want %q", o.cfg.GroupsClaim, defaultGroupsClaim)
	}
	if o.cfg.ButtonLabel != defaultButtonLabel {
		t.Errorf("button label = %q, want %q", o.cfg.ButtonLabel, defaultButtonLabel)
	}
	if want := []string{"openid", "profile", "email"}; !reflect.DeepEqual(o.cfg.Scopes, want) {
		t.Errorf("scopes = %v, want %v", o.cfg.Scopes, want)
	}
}

func TestNewOIDCAuthOverrides(t *testing.T) {
	o := newOIDCAuth(map[string]string{
		"oidc_issuer":        "https://idp.example",
		"oidc_client_id":     "client-123",
		"oidc_default_role":  "admin",
		"oidc_groups_claim":  "roles",
		"oidc_admin_group":   "xodbox-admins",
		"oidc_button_label":  "Log in with Corp SSO",
		"oidc_scopes":        "openid, email, groups",
		"oidc_redirect_url":  "https://oob.example.com/admin/api/auth/oidc/callback",
		"oidc_client_secret": "shh",
	})
	if o.cfg.DefaultRole != model.RoleAdmin {
		t.Errorf("default role = %q, want admin", o.cfg.DefaultRole)
	}
	if o.cfg.AdminGroup != "xodbox-admins" || o.cfg.GroupsClaim != "roles" {
		t.Errorf("group mapping not parsed: %+v", o.cfg)
	}
	if o.cfg.ClientSecret != "shh" || o.cfg.RedirectURL == "" {
		t.Errorf("secret/redirect not parsed: %+v", o.cfg)
	}
	if want := []string{"openid", "email", "groups"}; !reflect.DeepEqual(o.cfg.Scopes, want) {
		t.Errorf("scopes = %v, want %v", o.cfg.Scopes, want)
	}
}

func TestParseScopesAlwaysIncludesOpenID(t *testing.T) {
	if got := parseScopes("email profile"); got[0] != "openid" {
		t.Errorf("openid not prepended: %v", got)
	}
	if got := parseScopes(""); !reflect.DeepEqual(got, []string{"openid", "profile", "email"}) {
		t.Errorf("empty scopes default = %v", got)
	}
}

func TestClaimContains(t *testing.T) {
	cases := []struct {
		name  string
		claim any
		want  bool
	}{
		{"array of strings", []any{"a", "admins", "b"}, true},
		{"array missing", []any{"a", "b"}, false},
		{"typed slice", []string{"admins"}, true},
		{"space delimited (not a delimiter)", "a admins b", false},
		{"comma delimited", "a,admins,b", true},
		{"comma and space around value", "a, admins ,b", true},
		{"single miss", "user", false},
		{"nil", nil, false},
		{"wrong type", 42, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := claimContains(tc.claim, "admins"); got != tc.want {
				t.Errorf("claimContains(%v) = %v, want %v", tc.claim, got, tc.want)
			}
		})
	}
}

func TestRoleFor(t *testing.T) {
	o := &oidcAuth{cfg: oidcConfig{DefaultRole: model.RoleUser, GroupsClaim: "groups", AdminGroup: "admins"}}
	if r := o.roleFor(map[string]any{"groups": []any{"admins"}}); r != model.RoleAdmin {
		t.Errorf("admin group should map to admin, got %q", r)
	}
	if r := o.roleFor(map[string]any{"groups": []any{"users"}}); r != model.RoleUser {
		t.Errorf("non-admin should map to default, got %q", r)
	}
	// With no admin group configured, everyone gets the default role.
	o2 := &oidcAuth{cfg: oidcConfig{DefaultRole: model.RoleUser, GroupsClaim: "groups"}}
	if r := o2.roleFor(map[string]any{"groups": []any{"admins"}}); r != model.RoleUser {
		t.Errorf("without admin_group, role = %q, want user", r)
	}
}

func TestRedirectURLDerivation(t *testing.T) {
	o := &oidcAuth{cfg: oidcConfig{}}
	r := httptest.NewRequest(http.MethodGet, "http://console.local/admin/api/auth/oidc/login", nil)
	if got := o.redirectURL("/admin/", r); got != "http://console.local/admin/api/auth/oidc/callback" {
		t.Errorf("derived redirect = %q", got)
	}
	// X-Forwarded-Proto upgrades the scheme (admin behind a TLS proxy).
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := o.redirectURL("/admin/", r); !strings.HasPrefix(got, "https://") {
		t.Errorf("x-forwarded-proto not honored: %q", got)
	}
	// An explicit override wins.
	o.cfg.RedirectURL = "https://fixed.example/cb"
	if got := o.redirectURL("/admin/", r); got != "https://fixed.example/cb" {
		t.Errorf("override ignored: %q", got)
	}
}

func TestHandleProviders(t *testing.T) {
	// Disabled.
	a := newAdminAuth("/", false, nil, nil, nil)
	rec := httptest.NewRecorder()
	a.handleProviders(rec, httptest.NewRequest(http.MethodGet, "/api/auth/providers", nil))
	var off providersInfo
	_ = json.NewDecoder(rec.Body).Decode(&off)
	if off.OIDC.Enabled {
		t.Error("providers should report OIDC disabled")
	}

	// Enabled.
	o := newOIDCAuth(map[string]string{"oidc_issuer": "https://idp", "oidc_client_id": "c", "oidc_button_label": "SSO"})
	a2 := newAdminAuth("/", false, nil, o, nil)
	rec2 := httptest.NewRecorder()
	a2.handleProviders(rec2, httptest.NewRequest(http.MethodGet, "/api/auth/providers", nil))
	var on providersInfo
	_ = json.NewDecoder(rec2.Body).Decode(&on)
	if !on.OIDC.Enabled || on.OIDC.Label != "SSO" {
		t.Errorf("providers should report OIDC enabled with label: %+v", on)
	}
}

// TestOIDCCallbackRejectsBadState verifies the callback fails closed (before any
// network call to the IdP) when the state cookie is missing or does not match.
func TestOIDCCallbackRejectsBadState(t *testing.T) {
	o := newOIDCAuth(map[string]string{"oidc_issuer": "https://idp", "oidc_client_id": "c"})
	a := newAdminAuth("/", false, nil, o, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=attacker&code=x", nil)
	// No state cookie set.
	a.handleOIDCCallback(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "sso_error=invalid+state") {
		t.Errorf("expected invalid state redirect, got %q", loc)
	}
}

// TestOIDCRoutesMountOnlyWhenEnabled checks the login/callback routes are absent
// when OIDC is unconfigured, and present when it is.
func TestOIDCRoutesMountOnlyWhenEnabled(t *testing.T) {
	off := newAdminAuth("/", false, nil, nil, nil).mux()
	rec := httptest.NewRecorder()
	off.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("callback should 404 when OIDC disabled, got %d", rec.Code)
	}

	o := newOIDCAuth(map[string]string{"oidc_issuer": "https://idp", "oidc_client_id": "c"})
	on := newAdminAuth("/", false, nil, o, nil).mux()
	rec2 := httptest.NewRecorder()
	// Missing state → 302 redirect (route exists), not 404.
	on.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback", nil))
	if rec2.Code != http.StatusFound {
		t.Errorf("callback should be routed when OIDC enabled, got %d", rec2.Code)
	}
}
