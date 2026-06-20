package discord

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defektive/xodbox/pkg/types"
)

func TestLgReturnsLogger(t *testing.T) {
	if lg() == nil {
		t.Fatal("lg() returned nil")
	}
	// second call exercises the memoized branch
	if lg() == nil {
		t.Fatal("lg() returned nil on second call")
	}
}

// TestSendNetworkErrorPropagates verifies that a transport-level failure from
// the underlying webhook.SendPost is returned by Send (filter matches first).
func TestSendNetworkErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // connection will be refused

	n := NewNotifier(map[string]string{"url": url, "filter": ".*"}).(*Notifier)
	if err := n.Send(&types.BaseEvent{RawData: []byte("body")}); err == nil {
		t.Error("Send to closed server should return error")
	}
}

// TestSendNon2xxReturnsNil pins the current behaviour: webhook.SendPost logs
// but returns nil on a >=400 response, so Send also returns nil.
func TestSendNon2xxReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	n := NewNotifier(map[string]string{"url": srv.URL, "filter": ".*"}).(*Notifier)
	if err := n.Send(&types.BaseEvent{RawData: []byte("body")}); err != nil {
		t.Errorf("Send on 503 = %v, want nil (current behaviour)", err)
	}
}
