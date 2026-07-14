package httpx

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/defektive/xodbox/pkg/model"
	"golang.org/x/oauth2"
)

const (
	oidcStateCookie    = "xodbox_oidc_state"
	oidcNonceCookie    = "xodbox_oidc_nonce"
	oidcVerifierCookie = "xodbox_oidc_verifier"
	oidcTempTTL        = 10 * time.Minute
	defaultButtonLabel = "Sign in with SSO"
	defaultGroupsClaim = "groups"
)

// oidcConfig is the parsed OIDC configuration for one admin surface. A nil
// *oidcAuth (built from this) means OIDC is disabled and no SSO routes mount.
type oidcConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURL, when set, overrides the callback URL derived from the
	// request. It must exactly match a redirect URI registered with the IdP.
	RedirectURL string
	Scopes      []string
	DefaultRole string
	// GroupsClaim is the ID-token claim inspected for AdminGroup membership.
	GroupsClaim string
	// AdminGroup, when set and present in GroupsClaim, grants the admin role.
	// Empty means every OIDC user gets DefaultRole.
	AdminGroup  string
	ButtonLabel string
}

// oidcAuth carries the OIDC config plus a lazily-initialized provider. Discovery
// (a network call to the issuer) is deferred to the first login/callback so the
// server still starts when the IdP is unreachable, and unit tests can build the
// handler without network.
type oidcAuth struct {
	cfg oidcConfig

	mu       sync.Mutex
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// newOIDCAuth builds an *oidcAuth from the handler's raw config map, or nil when
// OIDC is not configured (issuer and client_id are the minimum required keys).
func newOIDCAuth(c map[string]string) *oidcAuth {
	issuer := strings.TrimSpace(c["oidc_issuer"])
	clientID := strings.TrimSpace(c["oidc_client_id"])
	if issuer == "" || clientID == "" {
		return nil
	}

	scopes := parseScopes(c["oidc_scopes"])

	role := model.RoleUser
	if strings.TrimSpace(c["oidc_default_role"]) == model.RoleAdmin {
		role = model.RoleAdmin
	}

	groupsClaim := strings.TrimSpace(c["oidc_groups_claim"])
	if groupsClaim == "" {
		groupsClaim = defaultGroupsClaim
	}

	label := strings.TrimSpace(c["oidc_button_label"])
	if label == "" {
		label = defaultButtonLabel
	}

	return &oidcAuth{cfg: oidcConfig{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: strings.TrimSpace(c["oidc_client_secret"]),
		RedirectURL:  strings.TrimSpace(c["oidc_redirect_url"]),
		Scopes:       scopes,
		DefaultRole:  role,
		GroupsClaim:  groupsClaim,
		AdminGroup:   strings.TrimSpace(c["oidc_admin_group"]),
		ButtonLabel:  label,
	}}
}

// parseScopes splits a comma/space separated scope list, defaulting to the
// standard OIDC set. "openid" is always present.
func parseScopes(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' })
	if len(fields) == 0 {
		return []string{oidc.ScopeOpenID, "profile", "email"}
	}
	hasOpenID := false
	out := make([]string, 0, len(fields)+1)
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if f == oidc.ScopeOpenID {
			hasOpenID = true
		}
		out = append(out, f)
	}
	if !hasOpenID {
		out = append([]string{oidc.ScopeOpenID}, out...)
	}
	return out
}

// ensure lazily performs OIDC discovery and caches the provider/verifier. Safe
// for concurrent use; a failed discovery is not cached so the next request
// retries.
func (o *oidcAuth) ensure(ctx context.Context) (*oidc.Provider, *oidc.IDTokenVerifier, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return o.provider, o.verifier, nil
	}
	provider, err := oidc.NewProvider(ctx, o.cfg.Issuer)
	if err != nil {
		return nil, nil, err
	}
	o.provider = provider
	o.verifier = provider.Verifier(&oidc.Config{ClientID: o.cfg.ClientID})
	return provider, o.verifier, nil
}

// oauth2Config builds the oauth2.Config for one request, binding the redirect
// URL resolved for that request's host/mount.
func (o *oidcAuth) oauth2Config(p *oidc.Provider, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     o.cfg.ClientID,
		ClientSecret: o.cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       o.cfg.Scopes,
	}
}

// redirectURL resolves the OIDC callback URL for this request: the explicit
// oidc_redirect_url override, or one derived from the request scheme, host, and
// admin mount path. Derivation is deterministic across the login and callback
// legs (same host + basePath), which the token exchange requires.
func (o *oidcAuth) redirectURL(basePath string, r *http.Request) string {
	if o.cfg.RedirectURL != "" {
		return o.cfg.RedirectURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if xf := r.Header.Get("X-Forwarded-Proto"); xf == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host + basePath + "api/auth/oidc/callback"
}

// --- handlers (methods on adminAuth so they reuse session + notify plumbing) ---

// handleOIDCLogin starts the Authorization Code + PKCE flow: it stashes a
// state, nonce, and PKCE verifier in short-lived cookies and redirects the
// browser to the provider's authorization endpoint.
func (a *adminAuth) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	o := a.oidc
	provider, _, err := o.ensure(r.Context())
	if err != nil {
		lg().Error("oidc discovery failed", "err", err)
		a.oidcFail(w, r, "sso unavailable")
		return
	}

	state := randToken(16)
	nonce := randToken(16)
	verifier := oauth2.GenerateVerifier()

	a.setOIDCTempCookie(w, r, oidcStateCookie, state)
	a.setOIDCTempCookie(w, r, oidcNonceCookie, nonce)
	a.setOIDCTempCookie(w, r, oidcVerifierCookie, verifier)

	cfg := o.oauth2Config(provider, o.redirectURL(a.basePath, r))
	authURL := cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOIDCCallback completes the flow: it validates state, exchanges the
// code (with the PKCE verifier), verifies the ID token and its nonce, maps the
// claims to a role, provisions/refreshes the user, and issues a normal session
// cookie before redirecting into the console.
func (a *adminAuth) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	o := a.oidc

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		a.oidcFail(w, r, errParam)
		return
	}

	stateCookie, err := r.Cookie(oidcStateCookie)
	if err != nil || stateCookie.Value == "" ||
		subtle.ConstantTimeCompare([]byte(stateCookie.Value), []byte(r.URL.Query().Get("state"))) != 1 {
		a.oidcFail(w, r, "invalid state")
		return
	}
	verifierCookie, err := r.Cookie(oidcVerifierCookie)
	if err != nil || verifierCookie.Value == "" {
		a.oidcFail(w, r, "invalid session")
		return
	}
	nonceCookie, err := r.Cookie(oidcNonceCookie)
	if err != nil || nonceCookie.Value == "" {
		a.oidcFail(w, r, "invalid session")
		return
	}

	provider, verifier, err := o.ensure(r.Context())
	if err != nil {
		lg().Error("oidc discovery failed", "err", err)
		a.oidcFail(w, r, "sso unavailable")
		return
	}

	cfg := o.oauth2Config(provider, o.redirectURL(a.basePath, r))
	token, err := cfg.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(verifierCookie.Value))
	if err != nil {
		lg().Warn("oidc token exchange failed", "err", err)
		a.oidcFail(w, r, "token exchange failed")
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		a.oidcFail(w, r, "no id_token in response")
		return
	}
	idToken, err := verifier.Verify(r.Context(), rawID)
	if err != nil {
		lg().Warn("oidc id_token verification failed", "err", err)
		a.oidcFail(w, r, "id_token verification failed")
		return
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonceCookie.Value)) != 1 {
		a.oidcFail(w, r, "nonce mismatch")
		return
	}

	profile, err := o.profileFromToken(idToken)
	if err != nil {
		lg().Warn("oidc claim extraction failed", "err", err)
		a.oidcFail(w, r, "invalid claims")
		return
	}

	u, err := model.UpsertOIDCUser(profile)
	if err != nil {
		lg().Error("oidc user provisioning failed", "err", err)
		a.oidcFail(w, r, "provisioning failed")
		return
	}

	ip := peerIP(r)
	sessionToken, err := model.NewSession(u.ID, model.DefaultSessionTTL, r.UserAgent(), ip)
	if err != nil {
		a.oidcFail(w, r, "could not create session")
		return
	}
	a.clearOIDCTempCookies(w, r)
	a.setSessionCookie(w, r, sessionToken)
	a.notifyLogin(u.Username, ip, r.UserAgent())
	http.Redirect(w, r, a.basePath, http.StatusFound)
}

// profileFromToken extracts the identity and role-mapping claims from a verified
// ID token. The stored subject is namespaced by issuer so identities from
// different IdPs can never collide.
func (o *oidcAuth) profileFromToken(idToken *oidc.IDToken) (model.OIDCProfile, error) {
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return model.OIDCProfile{}, err
	}
	return model.OIDCProfile{
		Subject:           idToken.Issuer + "#" + idToken.Subject,
		Email:             stringClaim(claims, "email"),
		PreferredUsername: stringClaim(claims, "preferred_username"),
		Role:              o.roleFor(claims),
	}, nil
}

// roleFor maps ID-token claims to a xodbox role: admin when AdminGroup is
// configured and present in the configured groups claim, otherwise DefaultRole.
func (o *oidcAuth) roleFor(claims map[string]any) string {
	if o.cfg.AdminGroup != "" && claimContains(claims[o.cfg.GroupsClaim], o.cfg.AdminGroup) {
		return model.RoleAdmin
	}
	return o.cfg.DefaultRole
}

// stringClaim returns a string-typed claim, or "".
func stringClaim(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

// claimContains reports whether want appears in a groups-style claim, which may
// be a JSON array of strings or a comma-delimited string. Spaces are NOT used
// as delimiters for the string case because group names commonly contain spaces
// (e.g. "Platform Engineering"); splitting on spaces would fragment them and
// could grant unintended role elevation.
func claimContains(claim any, want string) bool {
	switch v := claim.(type) {
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == want {
				return true
			}
		}
	case string:
		for _, s := range strings.Split(v, ",") {
			if strings.TrimSpace(s) == want {
				return true
			}
		}
	}
	return false
}

// --- temp cookies (state/nonce/PKCE verifier) ---

// setOIDCTempCookie sets a short-lived cookie for the in-flight auth exchange.
// SameSite=Lax (not Strict) is required so the cookie survives the top-level
// redirect back from the IdP, which is a cross-site navigation.
func (a *adminAuth) setOIDCTempCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	// #nosec G124 -- Secure is set only over TLS on purpose (see setSessionCookie);
	// the admin console is commonly served over plain HTTP on localhost.
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     a.basePath,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(oidcTempTTL.Seconds()),
	})
}

func (a *adminAuth) clearOIDCTempCookies(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{oidcStateCookie, oidcNonceCookie, oidcVerifierCookie} {
		// #nosec G124 -- clearing only; see setOIDCTempCookie.
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     a.basePath,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
	}
}

// oidcFail aborts an SSO attempt by clearing the in-flight temp cookies (state,
// nonce, verifier) and then redirecting back to the console with an error
// marker the login page can surface. The clear must happen here, before the
// redirect commits the response headers via WriteHeader — any Set-Cookie added
// after WriteHeader is silently dropped by net/http.
func (a *adminAuth) oidcFail(w http.ResponseWriter, r *http.Request, reason string) {
	a.clearOIDCTempCookies(w, r)
	http.Redirect(w, r, a.basePath+"?sso_error="+url.QueryEscape(reason), http.StatusFound)
}

// providersInfo describes the enabled login providers for the SPA login page.
type providersInfo struct {
	OIDC oidcProviderInfo `json:"oidc"`
}

type oidcProviderInfo struct {
	Enabled bool   `json:"enabled"`
	Label   string `json:"label,omitempty"`
}

// handleProviders reports which external login providers are configured so the
// login page can render the SSO button only when OIDC is enabled. It is
// unauthenticated (like the CSRF endpoint) — it leaks nothing but a boolean and
// a button label.
func (a *adminAuth) handleProviders(w http.ResponseWriter, _ *http.Request) {
	info := providersInfo{}
	if a.oidc != nil {
		info.OIDC = oidcProviderInfo{Enabled: true, Label: a.oidc.cfg.ButtonLabel}
	}
	writeJSON(w, http.StatusOK, info)
}

// oidcSummary is used only for start-up logging.
func (o *oidcAuth) oidcSummary() string {
	return fmt.Sprintf("issuer=%s client_id=%s scopes=%s admin_group=%q",
		o.cfg.Issuer, o.cfg.ClientID, strings.Join(o.cfg.Scopes, ","), o.cfg.AdminGroup)
}
