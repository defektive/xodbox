package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defektive/xodbox/pkg/types"
)

func TestNoIndexBlocksTrailingSlash(t *testing.T) {
	h := &Handler{
		name:            "HTTPX",
		dispatchChannel: make(chan types.InteractionEvent, 4),
	}

	var nextHit bool
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextHit = true
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://x/static/", nil)
	req.RemoteAddr = "127.0.0.1:1234"

	h.noIndex(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
	if nextHit {
		t.Error("downstream handler should not be invoked for trailing-slash paths")
	}
}

func TestNoIndexDispatchesAndPassesThrough(t *testing.T) {
	ch := make(chan types.InteractionEvent, 4)
	h := &Handler{
		name:            "HTTPX",
		dispatchChannel: ch,
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusTeapot)
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://x/static/file.txt", nil)
	req.RemoteAddr = "198.51.100.1:33333"

	h.noIndex(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusTeapot {
		t.Errorf("status = %d, want 418", rr.Code)
	}
	if !nextCalled {
		t.Error("downstream handler should be invoked for non-trailing-slash paths")
	}
}
