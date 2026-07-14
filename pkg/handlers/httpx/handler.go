package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/analog-substance/util/fileutil"
	"github.com/caddyserver/certmagic"
	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
	"github.com/fsnotify/fsnotify"
	"github.com/libdns/namecheap"
	"github.com/libdns/route53"
	"gorm.io/gorm/clause"
)

const EmbeddedMountPoint = "/ixdbxi/"

type Handler struct {
	name               string
	Listener           string
	AutoCert           bool
	ACMEAccept         bool
	ACMEEmail          string
	ACMEURL            string
	DNSProvider        string
	DNSProviderAPIUser string
	DNSProviderAPIKey  string
	MDaaSLogLevel      string
	MDaaSBindListener  string
	MDaaSAllowedCIDR   string
	MDaaSNotifyURL     string
	TLSNames           []string
	APIPath            string
	APIToken           string
	BotExemptPrivate   bool

	UIPath        string
	UIAllowCIDRs  []*net.IPNet
	AdminListener string
	// MaxUploadSize is the per-file size cap (in bytes) when parsing
	// multipart/form-data uploads. 0 means no limit.
	MaxUploadSize int64
	// NotifyLogins, when true, emits an InteractionEvent on each successful
	// admin-UI login so it is recorded and fires notifiers whose Filter matches
	// the "HTTPX Login <user> from <ip>" string.
	NotifyLogins bool
	// PublicURL is the externally-reachable base URL of the honeypot HTTP
	// listener (e.g. "https://oob.example.com"). The admin UI uses it to build
	// copy-able links to a sink's slug. Empty = the UI falls back to its own
	// origin, which is correct when the UI is mounted on the honeypot listener.
	PublicURL string

	// oidc, when non-nil, enables OIDC/SSO login for the admin console. It is
	// built from the oidc_* config keys and nil when SSO is not configured.
	oidc *oidcAuth

	StaticDir       string
	dispatchChannel chan types.InteractionEvent
	app             types.App
	mux             *http.ServeMux

	mu                  sync.Mutex
	httpServer          *http.Server
	httpChallengeServer *http.Server // ACME HTTP-01 listener on :80 (HTTPS path only)
	httpsServer         *http.Server // TLS-terminated listener on :443
	adminServer         *http.Server // optional isolated admin UI listener
	watchCancel         context.CancelFunc
}

func NewHandler(handlerConfig map[string]string) types.Handler {

	staticDir := handlerConfig["static_dir"]
	payloadDir := handlerConfig["payload_dir"]
	listener := handlerConfig["listener"]
	tlsNamesOpt := handlerConfig["tls_names"]
	dnsProvider := handlerConfig["dns_provider"]
	dnsProviderAPIUser := handlerConfig["dns_provider_api_user"]
	dnsProviderAPIKey := handlerConfig["dns_provider_api_key"]
	acmeEmail := handlerConfig["acme_email"]
	acmeAccept := handlerConfig["acme_accept"] == "true"
	acmeURL := handlerConfig["acme_url"]

	mdaasLogLevel := handlerConfig["mdaas_log_level"]
	mdaasBindListener := handlerConfig["mdaas_bind_listener"]
	mdaasAllowedCIDR := handlerConfig["mdaas_allowed_cidr"]
	mdaasNotifyURL := handlerConfig["mdaas_notify_url"]

	// Exempt loopback/private/link-local sources from volume-based bot
	// detection by default — those are usually the operator or an internal
	// SSRF callback, and dropping them silently is a foot-gun. Set
	// bot_exempt_private: "false" to subject every source to bot detection.
	botExemptPrivate := handlerConfig["bot_exempt_private"] != "false"

	// Admin web UI: mounted under a normalized ui_path prefix (empty =
	// disabled). Access is restricted to ui_allow_cidrs (checked against the
	// real TCP peer IP) on top of the auth added in later phases.
	uiPath := handlerConfig["ui_path"]
	if uiPath != "" {
		if !strings.HasPrefix(uiPath, "/") {
			uiPath = "/" + uiPath
		}
		if !strings.HasSuffix(uiPath, "/") {
			uiPath = uiPath + "/"
		}
	}
	uiCIDRs, badCIDRs := parseCIDRs(handlerConfig["ui_allow_cidrs"])
	for _, b := range badCIDRs {
		lg().Warn("ignoring invalid ui_allow_cidrs entry", "entry", b)
	}
	// admin_listener isolates the admin UI on its own bind (e.g.
	// 127.0.0.1:9091), off the attacker-facing port. When set, the UI is
	// served there instead of on the main httpx listener.
	adminListener := handlerConfig["admin_listener"]

	// Optional: notify on admin logins and advertise a public base URL for the
	// admin UI's sink "copy link" control.
	notifyLogins := handlerConfig["notify_logins"] == "true"
	publicURL := strings.TrimRight(handlerConfig["public_url"], "/")

	maxUploadSize, _ := strconv.ParseInt(handlerConfig["max_upload_size"], 10, 64)

	// Optional OIDC/SSO login for the admin console. nil when unconfigured;
	// discovery is deferred to the first login so start-up never blocks on the
	// IdP.
	oidcAuth := newOIDCAuth(handlerConfig)
	if oidcAuth != nil {
		lg().Info("admin UI OIDC login enabled", "config", oidcAuth.oidcSummary())
	}

	if handlerConfig["api_token"] != "" {
		lg().Warn("api_token is deprecated; create admin users and API keys with 'xodbox user add' and the admin UI")
	}

	tlsNames := []string{}
	if tlsNamesOpt != "" {
		tlsNames = strings.Split(tlsNamesOpt, ",")
	}

	h := &Handler{
		name:               "HTTPX",
		Listener:           listener,
		StaticDir:          staticDir,
		AutoCert:           len(tlsNames) > 0,
		ACMEEmail:          acmeEmail,
		ACMEAccept:         acmeAccept,
		ACMEURL:            acmeURL,
		TLSNames:           tlsNames,
		DNSProvider:        dnsProvider,
		DNSProviderAPIUser: dnsProviderAPIUser,
		DNSProviderAPIKey:  dnsProviderAPIKey,
		MDaaSLogLevel:      mdaasLogLevel,
		MDaaSBindListener:  mdaasBindListener,
		MDaaSAllowedCIDR:   mdaasAllowedCIDR,
		MDaaSNotifyURL:     mdaasNotifyURL,
		APIPath:            handlerConfig["api_path"],
		APIToken:           handlerConfig["api_token"],
		BotExemptPrivate:   botExemptPrivate,
		MaxUploadSize:      maxUploadSize,
		UIPath:             uiPath,
		UIAllowCIDRs:       uiCIDRs,
		AdminListener:      adminListener,
		NotifyLogins:       notifyLogins,
		PublicURL:          publicURL,
		oidc:               oidcAuth,
	}

	if payloadDir != "" {
		lg().Debug("payload dir supplied", "payload_dir", payloadDir)
		CreatePayloadsFromDir(payloadDir, model.DB())
		watchCtx, cancel := context.WithCancel(context.Background())
		h.mu.Lock()
		h.watchCancel = cancel
		h.mu.Unlock()
		go watchForChanges(watchCtx, payloadDir)
	}

	return h
}

func (h *Handler) Name() string {
	return h.name
}

// Seed populates the bundled HTTPX payload templates into the database.
// Implements types.Seeder; called once by App.Run before Start. The
// underlying Seed function is idempotent.
func (h *Handler) Seed() error {
	Seed(model.DB())
	return nil
}
func (h *Handler) serverMux() *http.ServeMux {
	if h.mux == nil {
		h.mux = &http.ServeMux{}
		if h.StaticDir != "" {
			if !fileutil.DirExists(h.StaticDir) {
				if err := os.MkdirAll(h.StaticDir, 0750); err != nil {
					lg().Error("Failed to create static directory", "err", err)
				}
			}
			httpFS := http.FileServer(http.Dir(h.StaticDir))

			h.mux.Handle("/static/", http.StripPrefix("/static", h.noIndex(httpFS)))
		}

		if h.APIPath != "" {
			if !strings.HasPrefix(h.APIPath, "/") {
				h.APIPath = "/" + h.APIPath
			}

			if !strings.HasSuffix(h.APIPath, "/") {
				h.APIPath = h.APIPath + "/"
			}

			h.mux.Handle(h.APIPath, APIHAndler(h.APIPath, h.APIToken))
		}

		// Admin UI on the main listener: only when no isolated admin_listener
		// is configured. It is registered on its own prefix so it never falls
		// through to the honeypot catchall (no InteractionEvents for admin
		// traffic). Auth is layered on in a later phase.
		if h.AdminListener == "" && h.UIPath != "" && h.UIPath != "/" {
			h.mountUI(h.mux, h.UIPath)
		}

		subFs, err := fs.Sub(embeddedStaticFS, "static")
		if err != nil {
			lg().Error("Failed to subfs embedded files", "err", err)
		}
		h.mux.Handle(EmbeddedMountPoint, http.StripPrefix(EmbeddedMountPoint[:len(EmbeddedMountPoint)-1], h.noIndex(http.FileServer(http.FS(subFs)))))

		h.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			loadStart := time.Now()
			defer func() {
				lg().Debug("http response completed", "timeTaken", fmt.Sprintf("%dµs", time.Since(loadStart).Microseconds()))
			}()
			e := NewEvent(r)
			e.botExemptPrivate = h.BotExemptPrivate
			parseUploads(e, h.MaxUploadSize)
			e.Dispatch(h.dispatchChannel)

			for _, payload := range SortedPayloads() {
				if payload.ShouldProcess(r) {
					payload.Process(w, e, h)
					lg().Debug("Processing payload", "payload", payload, "IsFinal", payload.IsFinal)
					if payload.IsFinal {
						break
					}
				}
			}
		})

	}
	return h.mux
}

func (h *Handler) serveHTTP() error {
	httpSrv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      h.serverMux(),
		Addr:         h.Listener,
	}

	h.mu.Lock()
	h.httpServer = httpSrv
	h.mu.Unlock()

	return httpSrv.ListenAndServe()
}

func (h *Handler) serveHTTPS() error {
	certmagic.DefaultACME.Agreed = h.ACMEAccept
	certmagic.DefaultACME.Email = h.ACMEEmail
	certmagic.DefaultACME.CA = h.ACMEURL

	var provider certmagic.DNSProvider

	switch h.DNSProvider {
	case "namecheap":
		provider = &namecheap.Provider{
			User:   h.DNSProviderAPIUser,
			APIKey: h.DNSProviderAPIKey,
		}
	case "route53":
		provider = &route53.Provider{}
	}

	if provider != nil {
		certmagic.DefaultACME.DisableHTTPChallenge = true
		certmagic.DefaultACME.DisableTLSALPNChallenge = true
		certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				PropagationDelay: 30 * time.Second,
				DNSProvider:      provider,
			},
		}
	}

	return h.serveTLS(h.TLSNames, h.serverMux(), false)
}

// serveTLS provisions certificates for domainNames via certmagic,
// binds both the ACME HTTP-01 challenge listener (port 80) and the
// TLS listener (port 443), and serves until Stop is called. The
// resulting *http.Server instances are recorded on the Handler so
// Stop can shut them down gracefully. Blocks on the TLS Serve.
func (h *Handler) serveTLS(domainNames []string, mux http.Handler, forwardHTTP bool) error {
	ctx := context.Background()

	if mux == nil {
		mux = http.DefaultServeMux
	}

	cfg := certmagic.NewDefault()
	if err := cfg.ManageSync(ctx, domainNames); err != nil {
		return err
	}

	hln, err := net.Listen("tcp", fmt.Sprintf(":%d", certmagic.HTTPPort))
	if err != nil {
		return fmt.Errorf("acme challenge listener: %w", err)
	}

	tlsConfig := cfg.TLSConfig()
	tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)

	hsln, err := tls.Listen("tcp", fmt.Sprintf(":%d", certmagic.HTTPSPort), tlsConfig)
	if err != nil {
		hln.Close()
		return fmt.Errorf("tls listener: %w", err)
	}

	httpServer := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	if len(cfg.Issuers) > 0 {
		if am, ok := cfg.Issuers[0].(*certmagic.ACMEIssuer); ok {
			if forwardHTTP {
				httpServer.Handler = am.HTTPChallengeHandler(http.HandlerFunc(httpRedirectHandler))
			} else {
				httpServer.Handler = am.HTTPChallengeHandler(mux)
			}
		}
	}

	httpsServer := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       5 * time.Minute,
		Handler:           mux,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	h.mu.Lock()
	h.httpChallengeServer = httpServer
	h.httpsServer = httpsServer
	h.mu.Unlock()

	log.Printf("%v Serving HTTP->HTTPS on %s and %s", domainNames, hln.Addr(), hsln.Addr())

	go func() {
		if err := httpServer.Serve(hln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lg().Error("acme challenge server failed", "err", err)
		}
	}()

	if err := httpsServer.Serve(hsln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// mountUI registers the embedded admin SPA (CIDR-gated) on mux at the given
// normalized path prefix. path "/" mounts at the listener root (used by the
// isolated admin_listener); any other path is prefix-stripped.
func (h *Handler) mountUI(mux *http.ServeMux, path string) {
	handler, err := h.adminHandler(path)
	if err != nil {
		lg().Error("failed to init admin UI", "err", err)
		return
	}
	inner := handler
	if path != "/" {
		inner = http.StripPrefix(strings.TrimSuffix(path, "/"), handler)
	}
	mux.Handle(path, cidrAllowlist(h.UIAllowCIDRs, inner))
	lg().Info("admin UI mounted", "path", path, "allow_cidrs", len(h.UIAllowCIDRs))
}

// adminMux builds the mux for the isolated admin_listener: only the admin UI
// (and, in later phases, the admin API) — never the honeypot catchall.
func (h *Handler) adminMux() *http.ServeMux {
	mux := &http.ServeMux{}
	path := h.UIPath
	if path == "" {
		path = "/"
	}
	h.mountUI(mux, path)
	return mux
}

// startAdminServer binds and serves the isolated admin listener in the
// background (no-op when admin_listener is unset). A bind failure is returned
// synchronously so Start can surface it.
func (h *Handler) startAdminServer() error {
	if h.AdminListener == "" {
		return nil
	}
	srv := &http.Server{
		Addr:              h.AdminListener,
		Handler:           h.adminMux(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", h.AdminListener)
	if err != nil {
		return fmt.Errorf("admin listener %q: %w", h.AdminListener, err)
	}
	h.mu.Lock()
	h.adminServer = srv
	h.mu.Unlock()
	lg().Info("Starting admin UI server", "listener", h.AdminListener, "ui_path", h.UIPath)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lg().Error("admin server error", "err", err)
		}
	}()
	return nil
}

func (h *Handler) Start(app types.App, eventChan chan types.InteractionEvent) error {
	// capture these for later
	h.app = app
	h.dispatchChannel = eventChan

	if err := h.startAdminServer(); err != nil {
		return err
	}

	if h.AutoCert {
		lg().Info("Starting HTTPS server", "listener", h.Listener)
		return h.serveHTTPS()
	}

	lg().Info("Starting HTTP server", "listener", h.Listener)
	return h.serveHTTP()
}

// Stop shuts down whichever server(s) Start booted (plain HTTP, or
// the HTTPS pair of ACME-challenge + TLS server) and cancels the
// payload-directory watcher goroutine if one was started. Safe to
// call before Start or multiple times. Returns the first non-nil
// error encountered, but always attempts every shutdown.
func (h *Handler) Stop(ctx context.Context) error {
	h.mu.Lock()
	srv := h.httpServer
	challenge := h.httpChallengeServer
	tlsSrv := h.httpsServer
	admin := h.adminServer
	cancel := h.watchCancel
	h.watchCancel = nil
	h.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	var firstErr error
	shutdown := func(s *http.Server) {
		if s == nil {
			return
		}
		if err := s.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	shutdown(srv)
	shutdown(challenge)
	shutdown(tlsSrv)
	shutdown(admin)
	return firstErr
}

func (h *Handler) noIndex(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}

		e := NewEvent(r)
		e.botExemptPrivate = h.BotExemptPrivate
		parseUploads(e, h.MaxUploadSize)
		e.Dispatch(h.dispatchChannel)

		next.ServeHTTP(w, r)
	})
}

var watcher *fsnotify.Watcher

func watchForChanges(ctx context.Context, dirToWatch string) {
	// If ctx was already cancelled before this goroutine got to run
	// (common in tests that spin up a handler with payload_dir then
	// immediately Stop), skip the work entirely.
	select {
	case <-ctx.Done():
		return
	default:
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		lg().Error("creating fsnotify watcher", "err", err)
		return
	}
	defer w.Close()

	// watchDir is a filepath.Walk callback that accesses the package
	// global; set it before walking the tree.
	watcher = w

	if err := filepath.Walk(dirToWatch, watchDir); err != nil {
		lg().Error("error watching for changes", "err", err)
	}

	dbncr := Debounce(1 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return
		case event := <-w.Events:
			if strings.HasSuffix(event.Name, "~") {
				continue
			}

			lg().Debug("watcher.Event", "event", event)

			modifiedFilesMu.Lock()
			modifiedFiles[event.Name] = true
			modifiedFilesMu.Unlock()
			go dbncr(handleFileEvent)

		case err := <-w.Errors:
			lg().Error("watcher.Error", "err", err)
		}
	}
}

var (
	modifiedFilesMu sync.Mutex
	modifiedFiles   = map[string]bool{}
)

func watchDir(path string, fi os.FileInfo, err error) error {
	if err != nil {
		// filepath.Walk passes fi=nil when it couldn't stat the path
		// (e.g. directory was removed under us). Skip rather than
		// panic on fi.Mode().
		return nil
	}
	if fi.Mode().IsDir() {
		return watcher.Add(path)
	}

	return nil
}

// drainModifiedFiles returns a snapshot of pending paths and clears the
// map under the mutex, so the watcher goroutine can keep enqueuing
// without racing on map writes.
func drainModifiedFiles() []string {
	modifiedFilesMu.Lock()
	defer modifiedFilesMu.Unlock()
	out := make([]string, 0, len(modifiedFiles))
	for k := range modifiedFiles {
		out = append(out, k)
	}
	modifiedFiles = map[string]bool{}
	return out
}

func handleFileEvent() {
	for _, modifiedFile := range drainModifiedFiles() {
		// #nosec G304 -- path comes from the operator-controlled
		// payload_dir watched at startup, not from a request.
		f, err := os.Open(modifiedFile)
		if err != nil {
			lg().Error("error opening file", "file", modifiedFile, "err", err)
			continue
		}

		p, err := getPayloadsFromFrontmatter(f)
		if err != nil {
			lg().Error("error getting frontmatter", "file", modifiedFile, "err", err)
			continue
		}

		p.Project = model.DefaultProject()

		tx := model.DB().Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "name"}}, // key colume
			DoUpdates: clause.AssignmentColumns([]string{
				"description",
				"pattern",
				"is_final",
				"data",
				"sort_order",
				"internal_function",
			}), // column needed to be updated
		}).Create(&p)

		if tx.Error != nil {
			lg().Error("error creating payload", "err", tx.Error)
		} else {
			payloads = []*Payload{}
		}
	}
}

func Debounce(after time.Duration) func(f func()) {
	d := &debouncer{after: after}

	return func(f func()) {
		d.add(f)
	}
}

type debouncer struct {
	mu    sync.Mutex
	after time.Duration
	timer *time.Timer
}

func (d *debouncer) add(f func()) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil {
		d.timer.Stop()
	}
	d.timer = time.AfterFunc(d.after, f)
}

// (Previously defined a package-level HTTPS() helper plus a singleton
// set of certmagic listeners. Replaced by (*Handler).serveTLS so the
// Handler owns the server instances and Stop can shut them down.)

func httpRedirectHandler(w http.ResponseWriter, r *http.Request) {
	toURL := "https://"

	// since we redirect to the standard HTTPS port, we
	// do not need to include it in the redirect URL
	requestHost := hostOnly(r.Host)

	toURL += requestHost
	toURL += r.URL.RequestURI()

	// get rid of this disgusting unencrypted HTTP connection 🤢
	w.Header().Set("Connection", "close")

	http.Redirect(w, r, toURL, http.StatusMovedPermanently)
}

func hostOnly(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport // OK; probably had no port to begin with
	}
	return host
}
