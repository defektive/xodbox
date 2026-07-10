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
}

func NewEvent(req *http.Request) *Event {
	body, _ := io.ReadAll(req.Body)
	defer req.Body.Close()

	dump, _ := httputil.DumpRequest(req, false)
	dump = append(dump, body...)
	hostname, portNum := util.GetHostAndPortFromRequest(req)

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
	}
	return ev
}

// Interaction builds the persisted record for this request. The app event loop
// stores it (see types.Persistable); Headers carries the full request dump so
// CurlFromInteraction can reconstruct a replay curl.
func (e *Event) Interaction() *model.Interaction {
	protocol := "http"
	if e.req.TLS != nil {
		protocol = "https"
	}
	hostname, portNum := util.GetHostAndPortFromRequest(e.req)
	return &model.Interaction{
		RemoteAddr:    hostname,
		RemotePort:    fmt.Sprintf("%d", portNum),
		Handler:       "httpx",
		Protocol:      protocol,
		RequestType:   e.req.Method,
		RequestTarget: e.req.URL.Path,
		UserAgent:     e.req.UserAgent(),
		Headers:       string(e.requestHeader),
		Data:          e.body,
	}
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
	addr := e.BaseEvent.RemoteAddr

	// Loopback/private sources are usually the operator or an internal SSRF
	// callback, so (when enabled) they bypass volume-based bot detection —
	// otherwise a burst of local testing or captures silently stops
	// dispatching and every notifier goes quiet.
	exempt := e.botExemptPrivate && util.IsPrivateOrLoopback(addr)
	if !exempt && model.IsBot(addr) {
		lg().Warn("not dispatching suspected bot (high request volume); set bot_exempt_private to exempt local/private sources", "remote_addr", addr)
		return
	}

	go func() {
		cc <- e
	}()
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
