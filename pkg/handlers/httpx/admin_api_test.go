package httpx

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/defektive/xodbox/pkg/model"
)

func TestCurlFromInteraction(t *testing.T) {
	body := `{"user":"o'brien"}`
	i := &model.Interaction{
		Handler:     "httpx",
		Protocol:    "http",
		RequestType: "POST",
		Headers: "POST /x/ssrf?id=1 HTTP/1.1\r\n" +
			"Host: evil.example.com\r\n" +
			"Authorization: Bearer sekret\r\n" +
			"Content-Type: application/json\r\n\r\n" + body,
		Data: []byte(body),
	}
	got := CurlFromInteraction(i)
	for _, want := range []string{
		"curl -X POST 'http://evil.example.com/x/ssrf?id=1'",
		"-H 'Authorization: Bearer sekret'",
		`--data-raw '{"user":"o'\''brien"}'`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("curl missing %q:\n%s", want, got)
		}
	}
}

// getAuthed does a bearer-authenticated GET and returns the body.
func getAuthed(t *testing.T, url, key string) []byte {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", url, resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	return b
}

func TestInteractionsReadAPI(t *testing.T) {
	target := uniqueName("/p3")
	for i := 0; i < 3; i++ {
		model.DB().Create(&model.Interaction{
			Handler: "httpx", RemoteAddr: "10.0.0.1", RequestType: "GET",
			RequestTarget: target, Protocol: "http",
			Headers: "GET " + target + " HTTP/1.1\r\nHost: h\r\n\r\n",
		})
	}
	model.DB().Create(&model.Interaction{
		Handler: "httpx", RequestType: "GET", RequestTarget: uniqueName("/other"),
		Headers: "GET /other HTTP/1.1\r\nHost: h\r\n\r\n",
	})

	srv, _, u := adminTestServer(t)
	full, _, err := model.NewAPIKey(u.ID, "k", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Filtered list (webhook-style path view): exactly the 3 hits to target.
	var list struct {
		Items []interactionSummary `json:"items"`
		Total int                  `json:"total"`
	}
	_ = json.Unmarshal(getAuthed(t, srv.URL+"/api/interactions?target="+url.QueryEscape(target), full), &list)
	if list.Total != 3 || len(list.Items) != 3 {
		t.Fatalf("filtered list total=%d items=%d, want 3/3", list.Total, len(list.Items))
	}

	// Detail includes the raw request and a replay curl.
	id := list.Items[0].ID
	var detail interactionDetail
	_ = json.Unmarshal(getAuthed(t, fmt.Sprintf("%s/api/interactions/%d", srv.URL, id), full), &detail)
	if detail.RequestTarget != target {
		t.Errorf("detail target = %q, want %q", detail.RequestTarget, target)
	}
	if !strings.Contains(detail.Curl, "curl 'http://h"+target) {
		t.Errorf("detail curl = %q", detail.Curl)
	}

	// Dedicated curl endpoint.
	var cw struct {
		Curl string `json:"curl"`
	}
	_ = json.Unmarshal(getAuthed(t, fmt.Sprintf("%s/api/interactions/%d/curl", srv.URL, id), full), &cw)
	if !strings.HasPrefix(cw.Curl, "curl ") {
		t.Errorf("curl endpoint = %q", cw.Curl)
	}
}

func TestInteractionsRequireAuth(t *testing.T) {
	srv, _, _ := adminTestServer(t)
	resp, _ := http.Get(srv.URL + "/api/interactions")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauth /api/interactions = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestInteractionNotFound(t *testing.T) {
	srv, _, u := adminTestServer(t)
	full, _, _ := model.NewAPIKey(u.ID, "k", nil)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/interactions/99999999", nil)
	req.Header.Set("Authorization", "Bearer "+full)
	resp, _ := (&http.Client{}).Do(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing interaction = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}
