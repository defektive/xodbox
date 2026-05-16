package discord

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defektive/xodbox/pkg/types"
)

func TestNewNotifierWiresConfig(t *testing.T) {
	n := NewNotifier(map[string]string{
		"url":          "https://discord.test/hook",
		"author":       "xodbox-bot",
		"author_image": "https://x/y.png",
		"filter":       "^POST",
	}).(*Notifier)

	if n.User != "xodbox-bot" {
		t.Errorf("User = %q, want xodbox-bot", n.User)
	}
	if n.Icon != "https://x/y.png" {
		t.Errorf("Icon = %q", n.Icon)
	}
	if n.Name() != "discord" {
		t.Errorf("Name() = %q, want discord", n.Name())
	}
	if n.Filter().MatchString("GET /x") {
		t.Error("filter should not match GET")
	}
}

func TestPayloadFormatting(t *testing.T) {
	n := &Notifier{User: "u", Icon: "i"}
	out, err := n.Payload(&types.BaseEvent{RawData: []byte("body")})
	if err != nil {
		t.Fatalf("Payload err: %v", err)
	}

	var pd POSTData
	if err := json.Unmarshal(out, &pd); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pd.Username != "u" || pd.AvatarURL != "i" {
		t.Errorf("Payload header fields wrong: %+v", pd)
	}
	if !strings.Contains(pd.Content, "Default Event") || !strings.Contains(pd.Content, "body") {
		t.Errorf("Content missing details/data: %q", pd.Content)
	}
}

func TestSendFilterMatchPosts(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier(map[string]string{"url": srv.URL, "filter": ".*"}).(*Notifier)
	if err := n.Send(&types.BaseEvent{RawData: []byte("x")}); err != nil {
		t.Fatalf("Send err: %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("hits = %d, want 1", atomic.LoadInt32(&hits))
	}
}

func TestSendFilterRejectSkipsPost(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	n := NewNotifier(map[string]string{"url": srv.URL, "filter": "^impossible$"}).(*Notifier)
	if err := n.Send(&types.BaseEvent{RawData: []byte("body")}); err != nil {
		t.Fatalf("Send err: %v", err)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Errorf("hits = %d, want 0 (filter should block)", atomic.LoadInt32(&hits))
	}
}
