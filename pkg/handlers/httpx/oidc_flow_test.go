package httpx

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/model"
	jose "github.com/go-jose/go-jose/v4"
)

// mockIdP is a minimal OIDC provider for tests: discovery, JWKS, a stateful
// authorize endpoint (records nonce + PKCE challenge per code), and a token
// endpoint that returns a signed ID token echoing that nonce.
type mockIdP struct {
	*httptest.Server
	key      *rsa.PrivateKey
	clientID string
	// per-code state captured at /authorize and consumed at /token.
	mu     sync.Mutex
	codes  map[string]codeState
	groups []string
	email  string
	sub    string
}

type codeState struct {
	nonce     string
	challenge string
}

func newMockIdP(t *testing.T, clientID string) *mockIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	m := &mockIdP{
		key:      key,
		clientID: clientID,
		codes:    map[string]codeState{},
		sub:      "user-abc-123",
		email:    "operator@example.com",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/jwks", m.handleJWKS)
	mux.HandleFunc("/authorize", m.handleAuthorize)
	mux.HandleFunc("/token", m.handleToken)
	m.Server = httptest.NewServer(mux)
	t.Cleanup(m.Close)
	return m
}

func (m *mockIdP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                m.URL,
		"authorization_endpoint":                m.URL + "/authorize",
		"token_endpoint":                        m.URL + "/token",
		"jwks_uri":                              m.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (m *mockIdP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &m.key.PublicKey,
		KeyID:     "test-key",
		Algorithm: "RS256",
		Use:       "sig",
	}}}
	writeJSON(w, http.StatusOK, set)
}

func (m *mockIdP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := "code-" + q.Get("state")
	m.mu.Lock()
	m.codes[code] = codeState{nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
	m.mu.Unlock()

	redirect, _ := url.Parse(q.Get("redirect_uri"))
	rq := redirect.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	redirect.RawQuery = rq.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (m *mockIdP) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	code := r.FormValue("code")
	verifier := r.FormValue("code_verifier")

	m.mu.Lock()
	st, ok := m.codes[code]
	m.mu.Unlock()
	if !ok {
		http.Error(w, "unknown code", http.StatusBadRequest)
		return
	}
	// Enforce PKCE: S256(verifier) must equal the stored challenge.
	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != st.challenge {
		http.Error(w, "pkce mismatch", http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": "at-xyz",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     m.signIDToken(st.nonce),
	})
}

func (m *mockIdP) signIDToken(nonce string) string {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: m.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	if err != nil {
		panic(err)
	}
	now := time.Now()
	m.mu.Lock()
	claims := map[string]any{
		"iss":                m.URL,
		"sub":                m.sub,
		"aud":                m.clientID,
		"exp":                now.Add(time.Hour).Unix(),
		"iat":                now.Unix(),
		"nonce":              nonce,
		"email":              m.email,
		"preferred_username": m.email,
		"groups":             m.groups,
	}
	m.mu.Unlock()
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return compact
}

// oidcTestServer wires an admin surface at "/" with OIDC pointed at the mock IdP
// and a redirect-following cookie-jar client.
func oidcTestServer(t *testing.T, idp *mockIdP, extra map[string]string) (*httptest.Server, *http.Client) {
	t.Helper()
	cfg := map[string]string{
		"oidc_issuer":    idp.URL,
		"oidc_client_id": idp.clientID,
	}
	for k, v := range extra {
		cfg[k] = v
	}
	h := &Handler{oidc: newOIDCAuth(cfg)}
	handler, err := h.adminHandler("/")
	if err != nil {
		t.Fatalf("adminHandler: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return srv, &http.Client{Jar: jar}
}

// TestOIDCLoginFlowProvisionsUser drives the whole browser flow (login →
// authorize → callback) and asserts a user is provisioned and a session issued.
func TestOIDCLoginFlowProvisionsUser(t *testing.T) {
	idp := newMockIdP(t, "xodbox-client")
	idp.sub = "flow-" + uniqueName("sub")
	idp.email = uniqueName("flow") + "@example.com"
	srv, client := oidcTestServer(t, idp, nil)

	resp, err := client.Get(srv.URL + "/api/auth/oidc/login")
	if err != nil {
		t.Fatalf("login flow: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final status = %d, want 200 (SPA)", resp.StatusCode)
	}

	// The session cookie should now resolve to the freshly provisioned user.
	me := getMe(t, client, srv.URL)
	if me.Username != idp.email {
		t.Errorf("provisioned username = %q, want %q", me.Username, idp.email)
	}
	if me.Role != model.RoleUser {
		t.Errorf("role = %q, want user", me.Role)
	}

	// The account is subject-linked and password-less.
	if u := model.UserForSubject(idp.URL + "#" + idp.sub); u == nil {
		t.Error("expected a subject-linked account")
	}
}

// TestOIDCLoginFlowAdminGroup verifies the admin role is granted when the
// configured group is present in the token.
func TestOIDCLoginFlowAdminGroup(t *testing.T) {
	idp := newMockIdP(t, "xodbox-client")
	idp.sub = "admin-" + uniqueName("sub")
	idp.email = uniqueName("admin") + "@example.com"
	idp.groups = []string{"everyone", "xodbox-admins"}

	srv, client := oidcTestServer(t, idp, map[string]string{
		"oidc_admin_group": "xodbox-admins",
	})

	resp, err := client.Get(srv.URL + "/api/auth/oidc/login")
	if err != nil {
		t.Fatalf("login flow: %v", err)
	}
	resp.Body.Close()

	if me := getMe(t, client, srv.URL); me.Role != model.RoleAdmin {
		t.Errorf("role = %q, want admin (group mapping)", me.Role)
	}
}

type meView struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

func getMe(t *testing.T, c *http.Client, base string) meView {
	t.Helper()
	resp, err := c.Get(base + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me status = %d, want 200 (not logged in?)", resp.StatusCode)
	}
	var m meView
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode /api/me: %v", err)
	}
	return m
}
