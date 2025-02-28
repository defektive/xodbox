package httpx

import (
	"context"
	"fmt"
	"github.com/analog-substance/util/fileutil"
	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
	"github.com/foomo/simplecert"
	"github.com/foomo/tlsconfig"
	"github.com/fsnotify/fsnotify"
	"gorm.io/gorm/clause"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	autoCert := handlerConfig["autocert"] == "true"
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

func (h *Handler) Start(app types.App, eventChan chan types.InteractionEvent) error {
	// capture these for later
	h.app = app
	h.dispatchChannel = eventChan

	mux := &http.ServeMux{}
	if h.StaticDir != "" {
		if !fileutil.DirExists(h.StaticDir) {
			if err := os.MkdirAll(h.StaticDir, 0744); err != nil {
				lg().Error("Failed to create static directory", "err", err)
			}
		}
		fs := http.FileServer(http.Dir(h.StaticDir))

		mux.Handle("/static/", http.StripPrefix("/static", noIndex(fs)))
	}

	subFs, err := fs.Sub(embeddedStaticFS, "static")
	if err != nil {
		lg().Error("Failed to subfs embedded files", "err", err)
	}
	mux.Handle(EmbeddedMountPoint, http.StripPrefix(EmbeddedMountPoint[:len(EmbeddedMountPoint)-1], noIndex(http.FileServer(http.FS(subFs)))))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		loadStart := time.Now()
		defer func() {
			lg().Debug("http response completed", "timeTaken", fmt.Sprintf("%dµs", time.Since(loadStart).Microseconds()))
		}()
		e := NewEvent(r)

		e.Dispatch(h.dispatchChannel)

		for _, payload := range SortedPayloads() {
			if payload.ShouldProcess(r) {
				payload.Process(w, e, app.GetTemplateData())
				lg().Debug("Processing payload", "payload", payload, "IsFinal", payload.IsFinal)
				if payload.IsFinal {
					break
				}
			}
		}
	})

	if h.AutoCert {
		var (
			// the structure that handles reloading the certificate
			certReloader *simplecert.CertReloader
			numRenews    int
			ctx, cancel  = context.WithCancel(context.Background())
			tlsConf      = tlsconfig.NewServerTLSConfig(tlsconfig.TLSModeServerStrict)
			makeServer   = func() *http.Server {
				return &http.Server{
					ReadTimeout:  5 * time.Second,
					WriteTimeout: 5 * time.Second,
					IdleTimeout:  120 * time.Second,
					Addr:         h.Listener,
					Handler:      mux,
					TLSConfig:    tlsConf,
				}
			}
			srv = makeServer()
			cfg = simplecert.Default
		)

		// configure
		cfg.Domains = h.Domains
		cfg.CacheDir = h.CertCacheDir
		cfg.SSLEmail = h.CertEmail
		cfg.DNSProvider = h.CertDNSProvider
		cfg.DirectoryURL = h.AcmeDirectoryURL

		// disable HTTP challenges - we will only use the TLS challenge for this example.
		//cfg.HTTPAddress = ""

		// this function will be called just before certificate renewal starts and is used to gracefully stop the service
		// (we need to temporarily free port 443 in order to complete the TLS challenge)
		cfg.WillRenewCertificate = func() {
			// stop server
			cancel()
		}

		// this function will be called after the certificate has been renewed, and is used to restart your service.
		cfg.DidRenewCertificate = func() {
			numRenews++

			// restart server: both context and server instance need to be recreated!
			ctx, cancel = context.WithCancel(context.Background())
			srv = makeServer()

			// force reload the updated cert from disk
			certReloader.ReloadNow()

			// here we go again
			go serve(ctx, srv)
		}

		// init simplecert configuration
		// this will block initially until the certificate has been obtained for the first time.
		// on subsequent runs, simplecert will load the certificate from the cache directory on disk.
		certReloader, err = simplecert.Init(cfg, func() {
			os.Exit(0)
		})

		if err != nil {
			log.Fatal("simplecert init failed: ", err)
		}

		// redirect HTTP to HTTPS
		//log.Println("starting HTTP Listener on Port 80")
		//go http.ListenAndServe(":80", http.HandlerFunc(simplecert.Redirect))

		// enable hot reload
		tlsConf.GetCertificate = certReloader.GetCertificateFunc()
		serve(ctx, srv)

		fmt.Println("waiting forever")
		<-make(chan bool)
	} else {
		lg().Debug("http server listening on " + h.Listener)

		httpSrv := &http.Server{
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  120 * time.Second,
			Handler:      mux,
		}

		httpSrv.Addr = h.Listener
		lg().Info("Starting HTTP server", "listener", httpSrv.Addr)

		err = httpSrv.ListenAndServe()
		if err != nil {
			lg().Error("error starting HTTP server", "listener", httpSrv.Addr, "err", err)
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

//type HTTPServerHandler struct{}
//
//func (h HTTPServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
//	w.WriteHeader(http.StatusOK)
//	w.Write([]byte("hello from simplecert!"))
//}

func dumbServer(mux *http.ServeMux, listener string, domains []string, cacheDir, email, dnsProvider, directoryURL string) {

}

func serve(ctx context.Context, srv *http.Server) {

	// lets go
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %+s\n", err)
		}
	}()

	log.Printf("server started")
	<-ctx.Done()
	log.Printf("server stopped")

	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
	}()

	err := srv.Shutdown(ctxShutDown)
	if err == http.ErrServerClosed {
		log.Printf("server exited properly")
	} else if err != nil {
		log.Printf("server encountered an error on exit: %+s\n", err)
	}
}
