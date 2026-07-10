package httpx

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/analog-substance/util/cli/build_info"
	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
	"github.com/defektive/xodbox/pkg/util"
)

type Event struct {
	*types.BaseEvent
	req              *http.Request
	body             []byte
	requestHeader    []byte
	botExemptPrivate bool
	// interaction is a snapshot of the request built synchronously in NewEvent,
	// so the event loop can persist it without touching the live *http.Request
	// on another goroutine (which the handler may still be using or have freed).
	interaction *model.Interaction
}

func NewEvent(req *http.Request) *Event {
	body, _ := io.ReadAll(req.Body)
	defer req.Body.Close()

	dump, _ := httputil.DumpRequest(req, false)
	dump = append(dump, body...)
	hostname, portNum := util.GetHostAndPortFromRequest(req)

	protocol := "http"
	if req.TLS != nil {
		protocol = "https"
	}

	ev := &Event{
		BaseEvent: &types.BaseEvent{
			RemoteAddr:       hostname,
			RemotePortNumber: portNum,
			UserAgentString:  req.UserAgent(),
			RawData:          dump,
		},
		req:              req,
		body:             body,
		requestHeader:    dump,
		botExemptPrivate: true,
		interaction: &model.Interaction{
			RemoteAddr:    hostname,
			RemotePort:    fmt.Sprintf("%d", portNum),
			Handler:       "httpx",
			Protocol:      protocol,
			RequestType:   req.Method,
			RequestTarget: req.URL.Path,
			UserAgent:     req.UserAgent(),
			Headers:       string(dump), // full request dump for curl reconstruction
			Data:          body,
		},
	}
	return ev
}

// Interaction returns the record snapshotted in NewEvent (see types.Persistable).
func (e *Event) Interaction() *model.Interaction {
	return e.interaction
}

func (e *Event) Details() string {
	return fmt.Sprintf("HTTPX: %s %s from %s", e.req.Method, e.req.URL.String(), e.req.RemoteAddr)
}

// FilterString returns "HTTPX <METHOD> <path?query> from <ip-chain>". The
// IP chain is the unique X-Forwarded-For + peer list, so filters can select
// on method, path, or any hop's source IP.
func (e *Event) FilterString() string {
	return fmt.Sprintf("HTTPX %s %s from %s",
		e.req.Method, e.req.URL.RequestURI(), strings.Join(util.RequestIPChain(e.req), ","))
}

func (e *Event) Body() []byte {
	return e.body
}

func (e *Event) RequestHeaders() []byte {
	return e.requestHeader
}

func (e *Event) RawRequest() []byte {
	return append(e.requestHeader, e.body...)
}

func (e *Event) Request() *http.Request {
	return e.req
}

func (e *Event) RemoteAddr() string {
	return e.BaseEvent.RemoteAddr
}

func (e *Event) Dispatch(cc chan types.InteractionEvent) {
	go func() {
		cc <- e
	}()
}

// NotifySuppressed reports whether notifiers should skip this event. Suspected
// bots (high request volume) are still persisted and shown in the Events log,
// but don't fire notifications — otherwise a scanner floods every notifier.
// Loopback/private sources are usually the operator or an internal SSRF
// callback, so (when enabled) they bypass volume-based bot detection.
func (e *Event) NotifySuppressed() bool {
	addr := e.BaseEvent.RemoteAddr
	exempt := e.botExemptPrivate && util.IsPrivateOrLoopback(addr)
	if !exempt && model.IsBot(addr) {
		lg().Warn("suppressing notifiers for suspected bot (high request volume); still recorded. Set bot_exempt_private to exempt local/private sources", "remote_addr", addr)
		return true
	}
	return false
}

func (e *Event) TemplateContext(templateData map[string]string) *TemplateContext {
	r := e.Request()

	remoteAddrs := []string{r.RemoteAddr}
	headerIP := r.Header.Get("X-Forwarded-For")
	if headerIP != "" {
		remoteAddrs = append(remoteAddrs, headerIP)
	}
	headerIP = r.Header.Get("X-Real-IP")
	if headerIP != "" {
		remoteAddrs = append(remoteAddrs, headerIP)
	}

	fullRequestBytes := e.RawRequest()

	tcr := &TemplateRequestContext{
		RemoteAddr:  remoteAddrs,
		UserAgent:   r.UserAgent(),
		Host:        r.Host,
		Path:        r.URL.Path,
		FullRequest: fullRequestBytes,
		Body:        e.Body(),
		Headers:     r.Header,
		GetParams:   r.URL.Query(),
		PostParams:  r.PostForm,
	}

	for param, vals := range r.URL.Query() {
		if len(vals) > 1 {
			for idx, val := range vals {
				templateData[fmt.Sprintf("GET_%s_%d", param, idx)] = val
			}
		} else if len(vals) == 1 {
			templateData[fmt.Sprintf("GET_%s", param)] = vals[0]
		}
	}

	tc := &TemplateContext{
		Version:          build_info.GetLoadedVersion().Version,
		NotifyString:     templateData["notify_string"],
		ServerName:       templateData["server_name"],
		CallBackImageURL: fmt.Sprintf("http://%s%s?&xdbxImage", r.Host, r.RequestURI),
		CallBackURL:      fmt.Sprintf("http://%s%s?&xdbx", r.Host, r.RequestURI),
		Extra:            templateData,
		Payloads:         model.SortedPayloads(),
		Request:          tcr,
	}

	return tc

}

type TemplateContext struct {
	Version          string
	NotifyString     string
	Uptime           time.Duration
	Payloads         []model.Payload
	CallBackImageURL string
	CallBackURL      string
	Extra            map[string]string
	ProxySrv         string
	ProxySrvRegex    string

	Request    *TemplateRequestContext
	ServerName string
}

type TemplateRequestContext struct {
	RemoteAddr  []string
	Host        string
	Path        string
	UserAgent   string
	FullRequest []byte
	Body        []byte

	Headers    map[string][]string
	GetParams  map[string][]string
	PostParams map[string][]string
}
