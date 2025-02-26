package httpx

import (
	"fmt"
	"github.com/analog-substance/util/fileutil"
	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const EmbeddedMountPoint = "/ixdbxi/"

type Handler struct {
	name     string
	Listener string
	AutoCert bool

	StaticDir       string
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
	listener := handlerConfig["listener"]
	autoCert := handlerConfig["autocert"] == "true"

	return &Handler{
		name:      "HTTPX",
		Listener:  listener,
		AutoCert:  autoCert,
		StaticDir: staticDir,
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

	domains := ""
	tlsDomains := strings.Split(domains, ",")

	if len(domains) > 0 {
		lg().Info("Listening on TLS Domains", "domains", tlsDomains)
		err := http.Serve(autocertListener(true, tlsDomains...), mux)
		if err != nil {
			lg().Error("error starting autocert HTTP server", "tlsDomains", tlsDomains, "err", err)
			return err
		}

	} else {

		httpSrv := &http.Server{
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  120 * time.Second,
			Handler:      mux,
		}

		httpSrv.Addr = h.Listener
		lg().Info("Starting HTTP server", "listener", httpSrv.Addr)

		err := httpSrv.ListenAndServe()
		if err != nil {
			lg().Error("error starting HTTP server", "listener", httpSrv.Addr, "err", err)
			return err
		}
	}

	return nil
}

type wrappedEvent struct {
	W            *http.ResponseWriter
	r            *http.Request
	app          types.App
	handler      types.Handler
	body         []byte
	templateData map[string]string
}

func autocertListener(staging bool, domains ...string) net.Listener {

	letsEncryptStaging := "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmeDirectoryURL := autocert.DefaultACMEDirectory

	if staging {
		acmeDirectoryURL = letsEncryptStaging
	}

	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Client: &acme.Client{
			DirectoryURL: acmeDirectoryURL,
		},
	}

	if len(domains) > 0 {
		m.HostPolicy = autocert.HostWhitelist(domains...)
	}

	dir := "certs"
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Printf("warning: autocert.NewListener not using a cache: %v", err)
	} else {
		m.Cache = autocert.DirCache(dir)
	}
	return m.Listener()
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
