package httpx

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
)

const (
	sessionCookie = "xodbox_session"
	csrfCookie    = "xodbox_csrf"
	csrfHeader    = "X-CSRF-Token"
	maxLoginBody  = 4096
)

type ctxKey int

const userCtxKey ctxKey = iota

// userFromContext returns the authenticated user attached by requireAuth.
func userFromContext(ctx context.Context) *model.User {
	u, _ := ctx.Value(userCtxKey).(*model.User)
	return u
}

// adminAuth holds the auth state for one mounted admin surface. basePath scopes
// the session/CSRF cookies to the mount point (ui_path or "/").
type adminAuth struct {
	basePath string
	limiter  *loginLimiter
	// notifyLogins gates emitting a login InteractionEvent on successful auth;
	// events is the app's dispatch channel it is sent on (nil when disabled or
	// when the handler hasn't started, e.g. in unit tests).
	notifyLogins bool
	events       chan types.InteractionEvent
	// oidc is non-nil when SSO is configured; it enables the OIDC login routes
	// and the SSO button on the login page.
	oidc *oidcAuth
}

func newAdminAuth(basePath string, notifyLogins bool, events chan types.InteractionEvent, oidcAuth *oidcAuth) *adminAuth {
	if basePath == "" {
		basePath = "/"
	}
	return &adminAuth{
		basePath:     basePath,
		limiter:      newLoginLimiter(10, time.Minute),
		notifyLogins: notifyLogins,
		events:       events,
		oidc:         oidcAuth,
	}
}

// mux builds the admin JSON API. Request paths are expected relative to the
// mount point (e.g. "/api/login"). Auth endpoints are session-cookie based for
// the browser; every authenticated route also accepts a bearer API key.
func (a *adminAuth) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/csrf", a.handleCSRF)
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("POST /api/logout", a.requireAuth(a.handleLogout))
	mux.HandleFunc("GET /api/me", a.requireAuth(a.handleMe))

	// External login providers. handleProviders is always available (reports
	// whether SSO is on); the OIDC routes mount only when configured. All three
	// are unauthenticated — they bootstrap or perform login.
	mux.HandleFunc("GET /api/auth/providers", a.handleProviders)
	if a.oidc != nil {
		mux.HandleFunc("GET /api/auth/oidc/login", a.handleOIDCLogin)
		mux.HandleFunc("GET /api/auth/oidc/callback", a.handleOIDCCallback)
	}

	// Read views (Phase 3).
	mux.HandleFunc("GET /api/interactions", a.requireAuth(a.handleInteractions))
	mux.HandleFunc("GET /api/interactions/{id}", a.requireAuth(a.handleInteraction))
	mux.HandleFunc("GET /api/interactions/{id}/curl", a.requireAuth(a.handleInteractionCurl))
	mux.HandleFunc("GET /api/interactions/{id}/files", a.requireAuth(a.handleInteractionFiles))
	mux.HandleFunc("GET /api/interactions/{id}/files/{fileID}", a.requireAuth(a.handleInteractionFileDownload))
	mux.HandleFunc("GET /api/bots", a.requireAuth(a.handleBots))

	// Payload CRUD (Phase 4). Payloads are global and control how the honeypot
	// responds to every inbound request, so mutations are admin-only. Reads stay
	// open to any authenticated operator.
	mux.HandleFunc("GET /api/payloads", a.requireAuth(a.handlePayloads))
	mux.HandleFunc("POST /api/payloads", a.requireAdmin(a.handleCreatePayload))
	mux.HandleFunc("GET /api/payloads/{id}", a.requireAuth(a.handlePayload))
	mux.HandleFunc("PUT /api/payloads/{id}", a.requireAdmin(a.handleUpdatePayload))
	mux.HandleFunc("DELETE /api/payloads/{id}", a.requireAdmin(a.handleDeletePayload))

	// Realtime: SSE stream of newly captured interactions (filterable).
	mux.HandleFunc("GET /api/stream", a.requireAuth(a.handleStream))

	// Sinks: named/described slugs with a per-slug event feed.
	mux.HandleFunc("GET /api/sinks", a.requireAuth(a.handleSinks))
	mux.HandleFunc("POST /api/sinks", a.requireAuth(a.handleCreateSink))
	mux.HandleFunc("GET /api/sinks/{slug}", a.requireAuth(a.handleSink))
	mux.HandleFunc("PUT /api/sinks/{slug}", a.requireAuth(a.handleUpdateSink))
	mux.HandleFunc("DELETE /api/sinks/{slug}", a.requireAuth(a.handleDeleteSink))
	mux.HandleFunc("GET /api/sinks/{slug}/files", a.requireAuth(a.handleSinkFiles))

	// User management (admin) + account + API keys (Phase 5).
	mux.HandleFunc("GET /api/users", a.requireAdmin(a.handleUsers))
	mux.HandleFunc("POST /api/users", a.requireAdmin(a.handleCreateUser))
	mux.HandleFunc("DELETE /api/users/{id}", a.requireAdmin(a.handleDeleteUser))
	mux.HandleFunc("POST /api/users/{id}/password", a.requireAdmin(a.handleResetPassword))
	mux.HandleFunc("POST /api/account/password", a.requireAuth(a.handleAccountPassword))
	mux.HandleFunc("GET /api/apikeys", a.requireAuth(a.handleAPIKeys))
	mux.HandleFunc("POST /api/apikeys", a.requireAuth(a.handleCreateAPIKey))
	mux.HandleFunc("DELETE /api/apikeys/{id}", a.requireAuth(a.handleDeleteAPIKey))
	return mux
}

// --- request resolution + middleware ---

// resolveUser authenticates a request via a bearer API key or session cookie.
func (a *adminAuth) resolveUser(r *http.Request) (u *model.User, bearer bool) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		key := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		return model.UserForAPIKey(key), true
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		return model.UserForSession(c.Value), false
	}
	return nil, false
}

// requireAuth rejects unauthenticated requests. Cookie-authenticated mutating
// requests must also carry a valid CSRF token; bearer (API key) requests are
// CSRF-exempt because they present no ambient credentials.
func (a *adminAuth) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, bearer := a.resolveUser(r)
		if u == nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !bearer && isMutation(r.Method) && !csrfValid(r) {
			writeErr(w, http.StatusForbidden, "invalid csrf token")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userCtxKey, u)))
	}
}

func isMutation(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// --- handlers ---

type userView struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

func toUserView(u *model.User) userView {
	return userView{ID: u.ID, Username: u.Username, Role: u.Role}
}

func (a *adminAuth) handleCSRF(w http.ResponseWriter, r *http.Request) {
	token := a.issueCSRF(w, r)
	writeJSON(w, http.StatusOK, map[string]string{"csrfToken": token})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *adminAuth) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := peerIP(r)
	if !a.limiter.allow(ip) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}
	if !csrfValid(r) {
		writeErr(w, http.StatusForbidden, "invalid csrf token")
		return
	}
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBody)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	u, err := model.Authenticate(req.Username, req.Password)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	token, err := model.NewSession(u.ID, model.DefaultSessionTTL, r.UserAgent(), ip)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create session")
		return
	}
	a.setSessionCookie(w, r, token)
	a.notifyLogin(u.Username, ip, r.UserAgent())
	writeJSON(w, http.StatusOK, toUserView(u))
}

// notifyLogin dispatches a login InteractionEvent so a successful admin login is
// recorded and delivered to notifiers whose Filter matches. It is a no-op unless
// notify_logins is enabled and a dispatch channel is wired (both hold at
// runtime; unit tests that build the handler directly leave events nil).
func (a *adminAuth) notifyLogin(username, ip, userAgent string) {
	if !a.notifyLogins || a.events == nil {
		return
	}
	NewLoginEvent(username, ip, userAgent).Dispatch(a.events)
}

func (a *adminAuth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		model.DeleteSession(c.Value)
	}
	a.clearSessionCookie(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (a *adminAuth) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, toUserView(userFromContext(r.Context())))
}

// --- cookies ---

func (a *adminAuth) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	// #nosec G124 -- Secure is set only over TLS on purpose: the admin UI is
	// commonly served over HTTP on localhost/admin_listener, where a Secure
	// cookie would never be sent. HttpOnly + SameSite=Strict are enforced.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     a.basePath,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(model.DefaultSessionTTL.Seconds()),
	})
}

func (a *adminAuth) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	// #nosec G124 -- see setSessionCookie; this only clears the cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     a.basePath,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// --- CSRF (double-submit cookie) ---

// issueCSRF sets a non-HttpOnly CSRF cookie (so the SPA can echo it in the
// X-CSRF-Token header) and returns the token. Combined with SameSite=Strict on
// both cookies, a matching header+cookie proves the request is same-origin.
func (a *adminAuth) issueCSRF(w http.ResponseWriter, r *http.Request) string {
	token := randToken(32)
	// #nosec G124 -- HttpOnly is intentionally false: double-submit CSRF needs
	// the SPA to read this token and echo it in the X-CSRF-Token header. The
	// token is not a credential on its own. SameSite=Strict is enforced.
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    token,
		Path:     a.basePath,
		HttpOnly: false,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(model.DefaultSessionTTL.Seconds()),
	})
	return token
}

func csrfValid(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	if err != nil || c.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.Header.Get(csrfHeader))) == 1
}

// --- helpers ---

func randToken(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// --- login rate limiter ---

// loginLimiter is a fixed-window per-key limiter guarding the login endpoint
// against brute force. It counts every attempt (success or failure) per source
// IP within the window.
type loginLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{max: max, window: window, hits: map[string][]time.Time{}}
}

func (l *loginLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-l.window)
	var kept []time.Time
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, time.Now())
	l.hits[key] = kept
	return len(kept) <= l.max
}
