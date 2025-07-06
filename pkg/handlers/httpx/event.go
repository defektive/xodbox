package httpx

import (
	"fmt"
	"github.com/analog-substance/util/cli/build_info"
	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
	"github.com/defektive/xodbox/pkg/util"
	"io"
	"net/http"
	"net/http/httputil"
	"time"
)

type Event struct {
	*types.BaseEvent
	req           *http.Request
	body          []byte
	requestHeader []byte
}

func NewEvent(req *http.Request) *Event {
	body, _ := io.ReadAll(req.Body)
	defer req.Body.Close()

	dump, _ := httputil.DumpRequest(req, false)
	dump = append(dump, body...)
	hostname, portNum := util.HostAndPortFromRemoteAddr(req.RemoteAddr)

	return &Event{
		BaseEvent: &types.BaseEvent{
			RemoteAddr:       hostname,
			RemotePortNumber: portNum,
			UserAgentString:  req.UserAgent(),
			RawData:          dump,
		},
		req:           req,
		body:          body,
		requestHeader: dump,
	}
}

func (e *Event) Details() string {
	return fmt.Sprintf("HTTPX: %s %s from %s", e.req.Method, e.req.URL.String(), e.req.RemoteAddr)
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
	return e.req.RemoteAddr
}

func (e *Event) Dispatch(cc chan types.InteractionEvent) {
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
		NotifyString:     "l",
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

	Request *TemplateRequestContext
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
