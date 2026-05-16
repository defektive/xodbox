package slack

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
		"url":          "https://hooks.slack.test/x",
		"channel":      "#alerts",
		"author":       "xodbox",
		"author_image": ":robot_face:",
		"filter":       "^GET",
	}).(*Notifier)

	if n.Channel != "#alerts" {
		t.Errorf("Channel = %q, want #alerts", n.Channel)
	}
	if n.User != "xodbox" {
		t.Errorf("User = %q, want xodbox", n.User)
	}
	if n.Icon != ":robot_face:" {
		t.Errorf("Icon = %q, want :robot_face:", n.Icon)
	}
	if n.Name() != "slack" {
		t.Errorf("Name() = %q, want slack", n.Name())
	}
	if n.Filter().MatchString("DELETE /x") {
		t.Error("filter should not match DELETE")
	}
}

func TestPayloadFormatting(t *testing.T) {
	n := &Notifier{
		Notifier: nil, // not used in Payload
		Channel:  "#c",
		User:     "u",
		Icon:     ":i:",
	}
	out, err := n.Payload(&types.BaseEvent{RawData: []byte("body")})
	if err != nil {
		t.Fatalf("Payload err: %v", err)
	}

	var pd POSTData
	if err := json.Unmarshal(out, &pd); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pd.Channel != "#c" || pd.Username != "u" || pd.IconEmoji != ":i:" {
		t.Errorf("Payload header fields wrong: %+v", pd)
	}
	if !strings.Contains(pd.Text, "Default Event") || !strings.Contains(pd.Text, "body") {
		t.Errorf("Text body missing details/data: %q", pd.Text)
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

	n := NewNotifier(map[string]string{
		"url":    srv.URL,
		"filter": ".*",
	}).(*Notifier)

	if err := n.Send(&types.BaseEvent{RawData: []byte("anything")}); err != nil {
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

	n := NewNotifier(map[string]string{
		"url":    srv.URL,
		"filter": "^never-match$",
	}).(*Notifier)

	if err := n.Send(&types.BaseEvent{RawData: []byte("body")}); err != nil {
		t.Fatalf("Send err: %v", err)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Errorf("hits = %d, want 0 (filter should block)", atomic.LoadInt32(&hits))
	}
}
