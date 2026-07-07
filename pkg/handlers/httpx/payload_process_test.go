package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defektive/xodbox/pkg/types"
)

// newProcessHandler returns a Handler wired with a stub app and a buffered
// dispatch channel so Payload.Process (which reads handler.app via
// TemplateContext) can run hermetically.
func newProcessHandler(data map[string]string) *Handler {
	if data == nil {
		data = map[string]string{}
	}
	return &Handler{
		name:            "HTTPX",
		app:             &stubApp{data: data},
		dispatchChannel: make(chan types.InteractionEvent, 4),
	}
}

func TestProcessWritesBodyTemplate(t *testing.T) {
	p := newPayload(PayloadData{Body: "hello {{.NotifyString}}"})
	h := newProcessHandler(map[string]string{"notify_string": "world"})

	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/p", ""))
	rr := httptest.NewRecorder()
	p.Process(rr, e, h)

	if got := rr.Body.String(); got != "hello world" {
		t.Errorf("body = %q, want %q", got, "hello world")
	}
}

func TestProcessSetsHeadersAndStatus(t *testing.T) {
	p := newPayload(PayloadData{
		Headers:    map[string]string{"X-Custom": "v1"},
		StatusCode: "418",
		Body:       "teapot",
	})
	h := newProcessHandler(nil)

	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/p", ""))
	rr := httptest.NewRecorder()
	p.Process(rr, e, h)

	if rr.Code != http.StatusTeapot {
		t.Errorf("status = %d, want 418", rr.Code)
	}
	if got := rr.Header().Get("X-Custom"); got != "v1" {
		t.Errorf("X-Custom = %q, want v1", got)
	}
	if rr.Body.String() != "teapot" {
		t.Errorf("body = %q, want teapot", rr.Body.String())
	}
}

// A Content-Type: text/html header should flip the payload into HTML
// templating mode (isHTMLContentType), causing output to be escaped.
func TestProcessHTMLContentTypeEscapes(t *testing.T) {
	p := newPayload(PayloadData{
		Headers: map[string]string{"Content-Type": "text/html"},
		Body:    "{{.NotifyString}}",
	})
	h := newProcessHandler(map[string]string{"notify_string": "<script>"})

	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/p", ""))
	rr := httptest.NewRecorder()
	p.Process(rr, e, h)

	if !p.isHTMLContentType {
		t.Error("isHTMLContentType should be set after Content-Type: text/html header")
	}
	if strings.Contains(rr.Body.String(), "<script>") {
		t.Errorf("html mode should have escaped output, got %q", rr.Body.String())
	}
}

// A non-numeric status template should fall back to HTTP 500.
func TestProcessInvalidStatusFallsBackTo500(t *testing.T) {
	p := newPayload(PayloadData{
		StatusCode: "not-a-number",
		Body:       "x",
	})
	h := newProcessHandler(nil)

	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/p", ""))
	rr := httptest.NewRecorder()
	p.Process(rr, e, h)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for non-numeric status template", rr.Code)
	}
}

// A redirect (Location header) implies HasStatusCode; with an empty status
// template the Atoi fails and we fall back to 500, but the Location header
// must still be written.
func TestProcessRedirectSetsLocation(t *testing.T) {
	p := newPayload(PayloadData{
		Headers: map[string]string{"Location": "https://example.com/elsewhere"},
	})
	h := newProcessHandler(nil)

	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/p", ""))
	rr := httptest.NewRecorder()
	p.Process(rr, e, h)

	if got := rr.Header().Get("Location"); got != "https://example.com/elsewhere" {
		t.Errorf("Location = %q, want https://example.com/elsewhere", got)
	}
}

// Process should dispatch to the internal "inspect" function when set,
// short-circuiting the body template.
func TestProcessInternalFunctionInspect(t *testing.T) {
	p := newPayload(PayloadData{Body: "SHOULD-NOT-APPEAR"})
	p.InternalFunction = InternalFnInspect
	h := newProcessHandler(nil)

	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/l/pizza", "reqbody"))
	rr := httptest.NewRecorder()
	p.Process(rr, e, h)

	body := rr.Body.String()
	if strings.Contains(body, "SHOULD-NOT-APPEAR") {
		t.Error("internal function should short-circuit body template")
	}
	if !strings.Contains(body, "Text Request") {
		t.Errorf("inspect should have produced a Text Request response, got %q", body)
	}
}

// An unknown internal function name should fall through to body templating.
func TestProcessUnknownInternalFunctionFallsThrough(t *testing.T) {
	p := newPayload(PayloadData{Body: "fallthrough-body"})
	p.InternalFunction = "does-not-exist"
	h := newProcessHandler(nil)

	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/p", ""))
	rr := httptest.NewRecorder()
	p.Process(rr, e, h)

	if !strings.Contains(rr.Body.String(), "fallthrough-body") {
		t.Errorf("unknown internal function should fall through to body, got %q", rr.Body.String())
	}
}

// A body template that fails to parse should produce the error fallback text.
func TestProcessBodyTemplateParseErrorFallback(t *testing.T) {
	p := newPayload(PayloadData{Body: "{{ .Unclosed "})
	h := newProcessHandler(nil)

	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/p", ""))
	rr := httptest.NewRecorder()
	p.Process(rr, e, h)

	if !strings.Contains(rr.Body.String(), "that was unexpected") {
		t.Errorf("malformed body template should write fallback text, got %q", rr.Body.String())
	}
}
