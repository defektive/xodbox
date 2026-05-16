package webhook

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync/atomic"
	"testing"

	"github.com/defektive/xodbox/pkg/types"
)

func TestNewNotifierDefaults(t *testing.T) {
	n := NewNotifier("https://example.com/hook", "")
	if n.Name() != "WebhookNotifier" {
		t.Errorf("Name() = %q, want WebhookNotifier", n.Name())
	}
	if !n.Filter().MatchString("anything goes") {
		t.Error("empty filter should compile to .* and match everything")
	}
}

func TestNewNotifierCustomFilter(t *testing.T) {
	n := NewNotifier("https://example.com/hook", "^GET /alert")
	if n.Filter().MatchString("DELETE /x") {
		t.Error("custom filter should reject non-matching data")
	}
	if !n.Filter().MatchString("GET /alert/pizza") {
		t.Error("custom filter should accept matching data")
	}
}

func TestSendPostSuccess(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		if string(body) != `{"ok":true}` {
			t.Errorf("body = %q, want %q", body, `{"ok":true}`)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := SendPost(srv.URL, []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("SendPost err: %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("server hits = %d, want 1", atomic.LoadInt32(&hits))
	}
}

func TestSendPostErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("nope"))
	}))
	defer srv.Close()

	// Current implementation logs but returns nil on >=400 — preserve
	// the observable behaviour. This test pins it down.
	if err := SendPost(srv.URL, []byte(`{}`)); err != nil {
		t.Errorf("SendPost on 500 err = %v, want nil (current behaviour)", err)
	}
}

func TestSendPostNetworkError(t *testing.T) {
	// Closed server URL → connection refused.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	if err := SendPost(url, []byte(`{}`)); err == nil {
		t.Error("SendPost to closed server should return error")
	}
}

func TestNotifierSendIntegration(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := &Notifier{
		name:   "WebhookNotifier",
		URL:    srv.URL,
		filter: regexp.MustCompile(".*"),
	}

	evt := &types.BaseEvent{
		RemoteAddr:       "1.2.3.4",
		RemotePortNumber: 1234,
		UserAgentString:  "ua",
		RawData:          []byte("hello"),
	}
	if err := n.Send(evt); err != nil {
		t.Fatalf("Send err: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("server received empty body")
	}
}
