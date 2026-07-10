package httpx

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/model"
)

// readLine reads one line from r, failing the test if nothing arrives in time.
func readLine(t *testing.T, lines <-chan string, timeout time.Duration) string {
	t.Helper()
	select {
	case l := <-lines:
		return l
	case <-time.After(timeout):
		t.Fatal("timed out waiting for stream line")
		return ""
	}
}

func TestInteractionStreamPushesFilteredEvents(t *testing.T) {
	srv, _, u := adminTestServer(t)
	key, _, err := model.NewAPIKey(u.ID, "k", nil)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/stream?handler=tcp", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	// Pump lines off the body so reads can be bounded by a timeout.
	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()

	// The ": connected" preamble is sent only after the handler subscribes, so
	// waiting for it avoids racing the publish below.
	for !strings.Contains(readLine(t, lines, 3*time.Second), "connected") {
	}

	// A non-matching event is filtered out; a matching one is delivered.
	model.PublishInteraction(&model.Interaction{Handler: "dns", RequestTarget: "x.example."})
	model.PublishInteraction(&model.Interaction{Handler: "tcp", RequestTarget: "/beacon", RemoteAddr: "10.0.0.9"})

	var sawEvent, sawData bool
	deadline := time.After(3 * time.Second)
	for !sawData {
		select {
		case l := <-lines:
			if strings.HasPrefix(l, "event: interaction") {
				sawEvent = true
			}
			if sawEvent && strings.HasPrefix(l, "data: ") {
				if !strings.Contains(l, `"handler":"tcp"`) || strings.Contains(l, `"handler":"dns"`) {
					t.Errorf("unexpected event data: %s", l)
				}
				sawData = true
			}
		case <-deadline:
			t.Fatal("did not receive the matching interaction event")
		}
	}
}

func TestInteractionStreamRequiresAuth(t *testing.T) {
	srv, _, _ := adminTestServer(t)
	resp, err := http.Get(srv.URL + "/api/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauth stream = %d, want 401", resp.StatusCode)
	}
}
