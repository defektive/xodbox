package httpx

import (
	"context"
	"errors"
	"fmt"
	"github.com/analog-substance/util/fileutil"
	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
	"github.com/foomo/simplecert"
	"github.com/foomo/tlsconfig"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"
)

const EmbeddedMountPoint = "/ixdbxi/"

type Handler struct {
	name       string
	Listener   string
	StaticDir  string
	PayloadDir string

	AutoCert         bool
	Domains          []string
	CertCacheDir     string
	CertEmail        string
	AcmeDirectoryURL string
	CertDNSProvider  string

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

	listenerIsHTTPS := strings.HasSuffix(listener, ":443") || strings.HasSuffix(listener, ":https")
	autoCert := listenerIsHTTPS && handlerConfig["autocert"] == "true"
	domains := handlerConfig["domains"]
	certCacheDir := handlerConfig["cert_cache_dir"]
	certEmail := handlerConfig["cert_email"]
	acmeDirectoryURL := handlerConfig["acme_dir_url"]

	// https://godoc.org/github.com/go-acme/lego/providers/dns
	// https://go-acme.github.io/lego/dns/
	dnsProvider := handlerConfig["cert_dns_provider"]

	envVars := handlerConfig["cert_dns_provider_env"]
	if envVars != "" {
		envVarsSlice := strings.Split(envVars, "\n")
		for _, envVar := range envVarsSlice {
			if strings.Contains(envVar, "=") {
				e := strings.Split(envVar, "=")
				os.Setenv(e[0], e[1])
			}
		}
	}

	if payloadDir != "" {
		lg().Debug("payload dir supplied", "payload_dir", payloadDir)
		CreatePayloadsFromDir(payloadDir, model.DB())
		go watchForChanges(payloadDir)
	}

	return &Handler{
		name:             "HTTPX",
		Listener:         listener,
		StaticDir:        staticDir,
		PayloadDir:       payloadDir,
		AutoCert:         autoCert,
		Domains:          strings.Split(domains, ","),
		CertCacheDir:     certCacheDir,
		CertEmail:        certEmail,
		AcmeDirectoryURL: acmeDirectoryURL,
		CertDNSProvider:  dnsProvider,
	}
}

func (h *Handler) Name() string {
	return h.name
}

func (h *Handler) ServerMux() *http.ServeMux {
	if h.mux == nil {

		h.mux = &http.ServeMux{}
		if h.StaticDir != "" {
			if !fileutil.DirExists(h.StaticDir) {
				if err := os.MkdirAll(h.StaticDir, 0744); err != nil {
					lg().Error("Failed to create static directory", "err", err)
				}
			}
			fs := http.FileServer(http.Dir(h.StaticDir))

			h.mux.Handle("/static/", http.StripPrefix("/static", noIndex(fs)))
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
					payload.Process(w, e, h.app.GetTemplateData())
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

func (h *Handler) Start(app types.App, eventChan chan types.InteractionEvent) error {
	// capture these for later
	h.app = app
	h.dispatchChannel = eventChan

	var makeBaseServer = func() *http.Server {
		lg().Info("Starting HTTP server", "listener", h.Listener)
		return &http.Server{
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  120 * time.Second,
			Handler:      h.ServerMux(),
			Addr:         h.Listener,
		}
	}

	var srv *http.Server

	if h.AutoCert {
		var (
			// the structure that handles reloading the certificate
			err          error
			certReloader *simplecert.CertReloader
			numRenews    int
			ctx, cancel  = context.WithCancel(context.Background())
			tlsConf      = tlsconfig.NewServerTLSConfig(tlsconfig.TLSModeServerStrict)
			makeServer   = func() *http.Server {
				srv := makeBaseServer()
				srv.TLSConfig = tlsConf
				return srv
			}

			cfg = simplecert.Default
		)

		srv = makeServer()

		// Useful for testing auto-renewals
		//cfg.RenewBefore = 2159
		//cfg.CheckInterval = 25 * time.Second

		// configure
		cfg.Domains = h.Domains
		cfg.CacheDir = h.CertCacheDir
		cfg.SSLEmail = h.CertEmail
		cfg.DNSProvider = h.CertDNSProvider
		cfg.DirectoryURL = h.AcmeDirectoryURL

		// if we fail to renew, we should send a special notification
		cfg.FailedToRenewCertificate = func(err error) {
			e := types.NewInternalEvent([]byte(err.Error()))
			e.RemoteAddr = fmt.Sprintf("xodbox-error-%s-%s", h.name, h.Listener)
			e.UserAgentString = fmt.Sprintf("user-agent-xodbox-error-%s-%s", h.name, h.Listener)

			// failed to renew cert
			h.dispatchChannel <- e
		}

		// if we specified a DNS Provider, lets use that
		if cfg.DNSProvider != "" {
			// disable HTTP and TLS challenges
			cfg.HTTPAddress = ""
			cfg.TLSAddress = ""
		}

		if cfg.DNSProvider == "" && cfg.HTTPAddress == "" {
			// cant do DNS or HTTP challenges
			// this means we'll have to stop the server
			// so we can listen on 443 for the challenge

			// this function will be called just before certificate renewal starts and is used to gracefully stop the service
			// (we need to temporarily free port 443 in order to complete the TLS challenge)
			// this is dumb. why not use port 80 and not disrupt the service that is running?
			// also if using DNS challenge why force TLS challenge for non-wildcard domains
			cfg.WillRenewCertificate = func() {
				lg().Info("certs will renew")
				if cfg.DNSProvider == "" && cfg.HTTPAddress == "" {
					// stop server
					cancel()
				}
			}
		}

		// this function will be called after the certificate has been renewed, and is used to restart your service.
		cfg.DidRenewCertificate = func() {
			lg().Info("certs renewed", "certReloader", certReloader)
			if certReloader == nil {
				// this only seemed to happen when a renewal was required at the time of the server start
				lg().Error("certs renewer is nil", "certReloader", certReloader)
				return
			}
			numRenews++

			if cfg.DNSProvider == "" && cfg.HTTPAddress == "" {
				// restart server: both context and server instance need to be recreated!
				ctx, cancel = context.WithCancel(context.Background())
				srv = makeServer()

				// force reload the updated cert from disk
				certReloader.ReloadNow()

				// here we go again
				go serveTLS(ctx, srv)
			} else {
				//
				//	// force reload the updated cert from disk
				certReloader.ReloadNow()
			}
		}

		// init simplecert configuration
		// this will block initially until the certificate has been obtained for the first time.
		// on subsequent runs, simplecert will load the certificate from the cache directory on disk.
		certReloader, err = simplecert.Init(cfg, func() {
			os.Exit(0)
		})

		if err != nil {
			lg().Error("simplecert init failed", "err", err)
		}

		// redirect HTTP to HTTPS
		//log.Println("starting HTTP Listener on Port 80")
		//go http.ListenAndServe(":80", http.HandlerFunc(simplecert.Redirect))

		// enable hot reload
		tlsConf.GetCertificate = certReloader.GetCertificateFunc()
		serveTLS(ctx, srv)
		<-make(chan bool)
	} else {
		srv = makeBaseServer()

		err := srv.ListenAndServe()
		if err != nil {
			lg().Error("error starting HTTP server", "listener", srv.Addr, "err", err)
			return err
		}
	}

	return nil
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

func serveTLS(ctx context.Context, srv *http.Server) {
	// start server in goroutine
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			lg().Error("failed to setup HTTPS server", "err", err)
		}
	}()

	// wait for server to be stopped
	<-ctx.Done()
	// server has been stopped

	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
	}()

	err := srv.Shutdown(ctxShutDown)
	if errors.Is(err, http.ErrServerClosed) {
		lg().Info("server exited properly")
	} else if err != nil {
		lg().Info("server exited with error", "err", err)
	}
}
