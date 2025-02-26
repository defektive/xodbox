package httpx

import (
	"fmt"
	"github.com/defektive/xodbox/pkg/types"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
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
