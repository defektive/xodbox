package httpx

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/defektive/xodbox/pkg/app/types"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type Handler struct {
	name        string
	Listener    string
	AutoCert    bool
	AlertPrefix string // Add alert prefix field

	dispatchChannel chan types.InteractionEvent
}

func NewHandler(handlerConfig map[string]string) types.Handler {

	listener := handlerConfig["listener"]
	autoCert := handlerConfig["autocert"] == "true"
	alertPrefix := handlerConfig["alert_prefix"]

	return &Handler{
		name:        "HTTPX",
		Listener:    listener,
		AutoCert:    autoCert,
		AlertPrefix: alertPrefix,
	}
}

type Event struct {
	*types.BaseEvent
	req *http.Request
}

func newHTTPEvent(req *http.Request, body []byte) types.InteractionEvent {
	remoteAddrURL := fmt.Sprintf("https://%s", req.RemoteAddr)
	parsedURL, _ := url.Parse(remoteAddrURL)
	portNum, _ := strconv.Atoi(parsedURL.Port())
	dump, _ := httputil.DumpRequest(req, false)
	dump = append(dump, body...)

	return &Event{
		BaseEvent: &types.BaseEvent{
			RemoteAddr:       parsedURL.Hostname(),
			RemotePortNumber: portNum,
			UserAgentString:  req.UserAgent(),
			RawData:          dump,
		},
		req: req,
	}
}

func (e *Event) Details() string {
	return fmt.Sprintf("HTTPX: %s %s://%s%s from %s", e.req.Method, "http", e.req.Host, e.req.URL.String(), e.req.RemoteAddr)
}

func (h *Handler) dispatchEvent(r *http.Request, body []byte) {
	if h.AlertPrefix != "" {
		if !strings.HasPrefix(r.URL.Path, h.AlertPrefix) {
			return
		}
	}
	h.dispatchChannel <- newHTTPEvent(r, body)
}

func (h *Handler) Name() string {
	return h.name
}

func (h *Handler) Start(eventChan chan types.InteractionEvent, app types.App) error {
	h.dispatchChannel = eventChan

	mux := &http.ServeMux{}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		loadStart := time.Now()
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		go h.dispatchEvent(r, body)

		for _, payload := range SortedPayloads() {
			if payload.ShouldHandle(r) {
				payload.Process(w, r, body, app.GetTemplateData())
			}
		}

		timeTaken := time.Now().Sub(loadStart)
		lg().Debug("http response completed", "timeTaken", timeTaken)
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
		log.Printf("warning: autocert.NewListener not using a cache: %v", err)
	} else {
		m.Cache = autocert.DirCache(dir)
	}
	return m.Listener()
}
