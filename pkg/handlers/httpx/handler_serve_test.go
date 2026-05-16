package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
)

type stubApp struct {
	data map[string]string
}

func (s *stubApp) Run()                                       {}
func (s *stubApp) RegisterNotificationHandler(types.Notifier) {}
func (s *stubApp) GetTemplateData() map[string]string {
	out := make(map[string]string, len(s.data))
	for k, v := range s.data {
		out[k] = v
	}
	return out
}

func TestServerMuxAPIRouted(t *testing.T) {
	h := NewHandler(map[string]string{
		"listener":  "127.0.0.1:0",
		"api_path":  "api",
		"api_token": "",
	}).(*Handler)
	h.app = &stubApp{data: map[string]string{}}
	h.dispatchChannel = make(chan types.InteractionEvent, 16)

	mux := h.serverMux()

	// APIPath should be normalised to leading + trailing slash.
	if h.APIPath != "/api/" {
		t.Errorf("APIPath normalisation: got %q, want /api/", h.APIPath)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("api/health status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"status":"ok"`) {
		t.Errorf("api/health body = %q", rr.Body.String())
	}
}

func TestServerMuxEmbeddedStaticAvailable(t *testing.T) {
	h := NewHandler(map[string]string{"listener": "127.0.0.1:0"}).(*Handler)
	h.app = &stubApp{data: map[string]string{}}
	h.dispatchChannel = make(chan types.InteractionEvent, 16)

	mux := h.serverMux()

	// Request the embedded mount root with trailing slash — noIndex
	// blocks directory listing, so we expect a 404 not a directory index.
	req := httptest.NewRequest(http.MethodGet, EmbeddedMountPoint, nil)
	req.RemoteAddr = "127.0.0.1:1"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("embedded directory request should be 404, got %d", rr.Code)
	}
}

func TestServerMuxDefaultRouteDispatchesEvent(t *testing.T) {
	// Clear payloads cache and table so payload processing is a no-op
	// for this test (we only assert the dispatch).
	payloads = nil
	t.Cleanup(func() { payloads = nil })
	if err := model.DB().Exec("DELETE FROM payloads").Error; err != nil {
		t.Fatalf("clear payloads: %v", err)
	}

	ch := make(chan types.InteractionEvent, 4)
	h := NewHandler(map[string]string{"listener": "127.0.0.1:0"}).(*Handler)
	h.app = &stubApp{data: map[string]string{}}
	h.dispatchChannel = ch

	mux := h.serverMux()

	req := httptest.NewRequest(http.MethodPost, "/some/path", strings.NewReader("body"))
	req.RemoteAddr = "203.0.113.7:55555"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	// Default handler does not write a status, so default is 200.
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}

	select {
	case evt := <-ch:
		if evt.RemoteIP() != "203.0.113.7" {
			t.Errorf("event RemoteIP = %q, want 203.0.113.7", evt.RemoteIP())
		}
	case <-time.After(time.Second):
		t.Fatal("expected dispatched event within 1s")
	}
}
