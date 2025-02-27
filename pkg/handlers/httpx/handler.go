package httpx

import (
	"fmt"
	"github.com/analog-substance/util/fileutil"
	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
	"github.com/fsnotify/fsnotify"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"gorm.io/gorm/clause"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	payloadDir := handlerConfig["payload_dir"]
	listener := handlerConfig["listener"]
	autoCert := handlerConfig["autocert"] == "true"

	if payloadDir != "" {
		lg().Debug("payload dir supplied", "payload_dir", payloadDir)
		CreatePayloadsFromDir(payloadDir, model.DB())
		go watchForChanges(payloadDir)
	}

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
		lg().Warn("autocert.NewListener not using a cache: %v", err)
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

				fileMods[event.Name] = true
				go dbncr(handleFileEvent)

			case err := <-watcher.Errors:
				lg().Error("watcher.Error", "err", err)
			}
		}
	}()

	<-done
}

var fileMods = map[string]bool{}

func watchDir(path string, fi os.FileInfo, err error) error {
	if fi.Mode().IsDir() {
		return watcher.Add(path)
	}

	return nil
}

func handleFileEvent() {
	for fileMod := range fileMods {
		delete(fileMods, fileMod)
		f, err := os.Open(fileMod)
		if err != nil {
			lg().Error("error opening file", "err", err)
			continue
		}

		p, err := getPayloadsFromFrontmatter(f)

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
