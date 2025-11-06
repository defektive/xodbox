package httpx

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
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

	StaticDir       string
	dispatchChannel chan types.InteractionEvent
	app             types.App
	mux             *http.ServeMux
}

func NewHandler(handlerConfig map[string]string) types.Handler {

	// I believe interface implementors should own seeding their data models
	// TODO: add method to interface to facilitate Seeding data.
	// data seeding cannot happen in an `init` function since we need input from the user
	// about what db to use
	// Seed data models
	Seed(model.DB())

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

	if payloadDir != "" {
		lg().Debug("payload dir supplied", "payload_dir", payloadDir)
		CreatePayloadsFromDir(payloadDir, model.DB())
		go watchForChanges(payloadDir)
	}

	tlsNames := []string{}
	if tlsNamesOpt != "" {
		tlsNames = strings.Split(tlsNamesOpt, ",")
	}

	return &Handler{
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
	}
}

func (h *Handler) Name() string {
	return h.name
}
func (h *Handler) serverMux() *http.ServeMux {
	if h.mux == nil {
		h.mux = &http.ServeMux{}
		if h.StaticDir != "" {
			if !fileutil.DirExists(h.StaticDir) {
				if err := os.MkdirAll(h.StaticDir, 0744); err != nil {
					lg().Error("Failed to create static directory", "err", err)
				}
			}
			httpFS := http.FileServer(http.Dir(h.StaticDir))

			h.mux.Handle("/static/", http.StripPrefix("/static", noIndex(httpFS)))
		}

		if h.APIPath != "" {
			if !strings.HasPrefix(h.APIPath, "/") {
				h.APIPath = "/" + h.APIPath
			}

			if !strings.HasSuffix(h.APIPath, "/") {
				h.APIPath = h.APIPath + "/"
			}

			h.mux.Handle(h.APIPath, APIHAndler(h.APIPath))
		}

		subFs, err := fs.Sub(embeddedStaticFS, "static")
		if err != nil {
			lg().Error("Failed to subfs embedded files", "err", err)
		}
		h.mux.Handle(EmbeddedMountPoint, http.StripPrefix(EmbeddedMountPoint[:len(EmbeddedMountPoint)-1], noIndex(http.FileServer(http.FS(subFs)))))

		h.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			loadStart := time.Now()
			defer func() {
				lg().Debug("http response completed", "timeTaken", fmt.Sprintf("%dµs", time.Since(loadStart).Microseconds()))
			}()
			e := NewEvent(r)

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

	// eventually we'll figure out what config options we want
	return HTTPS(h.TLSNames, h.serverMux(), false)
}

func (h *Handler) Start(app types.App, eventChan chan types.InteractionEvent) error {
	// capture these for later
	h.app = app
	h.dispatchChannel = eventChan

	if h.AutoCert {
		lg().Info("Starting HTTPS server", "listener", h.Listener)
		return h.serveHTTPS()
	}

	lg().Info("Starting HTTP server", "listener", h.Listener)
	return h.serveHTTP()
}

func noIndex(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

var watcher *fsnotify.Watcher

func watchForChanges(dirToWatch string) {
	watcher, _ = fsnotify.NewWatcher()
	defer watcher.Close()

	if err := filepath.Walk(dirToWatch, watchDir); err != nil {
		lg().Error("error watching for changes", "err", err)
	}
	done := make(chan bool)
	dbncr := Debounce(1 * time.Second)

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if strings.HasSuffix(event.Name, "~") {
					continue
				}

				lg().Debug("watcher.Error", "event", event)

				modifiedFiles[event.Name] = true
				go dbncr(handleFileEvent)

			case err := <-watcher.Errors:
				lg().Error("watcher.Error", "err", err)
			}
		}
	}()

	<-done
}

var modifiedFiles = map[string]bool{}

func watchDir(path string, fi os.FileInfo, err error) error {
	if fi.Mode().IsDir() {
		return watcher.Add(path)
	}

	return nil
}

func handleFileEvent() {
	for modifiedFile := range modifiedFiles {
		delete(modifiedFiles, modifiedFile)
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

// From Certmagic, since I am also opinionated... :D
// Variables for conveniently serving HTTPS.
var (
	httpLn, httpsLn net.Listener
	lnMu            sync.Mutex
	httpWg          sync.WaitGroup
)

func HTTPS(domainNames []string, mux http.Handler, forwardHTTP bool) error {
	ctx := context.Background()

	if mux == nil {
		mux = http.DefaultServeMux
	}

	cfg := certmagic.NewDefault()

	err := cfg.ManageSync(ctx, domainNames)
	if err != nil {
		return err
	}

	httpWg.Add(1)
	defer httpWg.Done()

	// if we haven't made listeners yet, do so now,
	// and clean them up when all servers are done
	lnMu.Lock()
	if httpLn == nil && httpsLn == nil {
		httpLn, err = net.Listen("tcp", fmt.Sprintf(":%d", certmagic.HTTPPort))
		if err != nil {
			lnMu.Unlock()
			return err
		}

		tlsConfig := cfg.TLSConfig()
		tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)

		httpsLn, err = tls.Listen("tcp", fmt.Sprintf(":%d", certmagic.HTTPSPort), tlsConfig)
		if err != nil {
			httpLn.Close()
			httpLn = nil
			lnMu.Unlock()
			return err
		}

		go func() {
			httpWg.Wait()
			lnMu.Lock()
			httpLn.Close()
			httpsLn.Close()
			lnMu.Unlock()
		}()
	}
	hln, hsln := httpLn, httpsLn
	//hsln := httpsLn
	lnMu.Unlock()

	// create HTTP/S servers that are configured
	// with sane default timeouts and appropriate
	// handlers (the HTTP server solves the HTTP
	// challenge and issues redirects to HTTPS,
	// while the HTTPS server simply serves the
	// user's handler)
	httpServer := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		BaseContext:       func(listener net.Listener) context.Context { return ctx },
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
		BaseContext:       func(listener net.Listener) context.Context { return ctx },
	}

	log.Printf("%v Serving HTTP->HTTPS on %s and %s", domainNames, hln.Addr(), hsln.Addr())

	go httpServer.Serve(hln)
	return httpsServer.Serve(hsln)
}

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
