package httpx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/defektive/xodbox/pkg/model"
)

// doAuthed performs a bearer-authenticated request with an optional JSON body.
func doAuthed(t *testing.T, method, url, key string, body any) *http.Response {
	t.Helper()
	var r *bytes.Reader
	req := (*http.Request)(nil)
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
		req, _ = http.NewRequest(method, url, r)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, _ = http.NewRequest(method, url, nil)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func TestPayloadCRUD(t *testing.T) {
	srv, _, u := adminTestServer(t)
	key, _, err := model.NewAPIKey(u.ID, "k", nil)
	if err != nil {
		t.Fatal(err)
	}
	base := srv.URL + "/api/payloads"

	// Create
	in := payloadView{
		Name:       "crud-" + t.Name(),
		Pattern:    "^/crud",
		Body:       "hello",
		StatusCode: "200",
		Headers:    map[string]string{"X-Test": "1"},
	}
	resp := doAuthed(t, http.MethodPost, base, key, in)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d, want 201", resp.StatusCode)
	}
	var created payloadView
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.ID == 0 {
		t.Fatal("create returned no id")
	}

	one := fmt.Sprintf("%s/%d", base, created.ID)

	// Get
	g := doAuthed(t, http.MethodGet, one, key, nil)
	var got payloadView
	_ = json.NewDecoder(g.Body).Decode(&got)
	g.Body.Close()
	if got.Body != "hello" || got.Headers["X-Test"] != "1" || got.StatusCode != "200" {
		t.Errorf("get mismatch: %+v", got)
	}

	// Update
	got.Body = "updated"
	got.Pattern = "^/crud2"
	up := doAuthed(t, http.MethodPut, one, key, got)
	if up.StatusCode != http.StatusOK {
		t.Fatalf("update = %d, want 200", up.StatusCode)
	}
	up.Body.Close()

	g2 := doAuthed(t, http.MethodGet, one, key, nil)
	var got2 payloadView
	_ = json.NewDecoder(g2.Body).Decode(&got2)
	g2.Body.Close()
	if got2.Body != "updated" || got2.Pattern != "^/crud2" {
		t.Errorf("update not applied: %+v", got2)
	}

	// Delete
	del := doAuthed(t, http.MethodDelete, one, key, nil)
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204", del.StatusCode)
	}
	del.Body.Close()

	g3 := doAuthed(t, http.MethodGet, one, key, nil)
	if g3.StatusCode != http.StatusNotFound {
		t.Errorf("get after delete = %d, want 404", g3.StatusCode)
	}
	g3.Body.Close()
}

func TestPayloadValidation(t *testing.T) {
	srv, _, u := adminTestServer(t)
	key, _, _ := model.NewAPIKey(u.ID, "k", nil)
	base := srv.URL + "/api/payloads"

	cases := map[string]payloadView{
		"invalid pattern": {Name: "bad-" + t.Name(), Pattern: "["},
		"missing name":    {Pattern: "^/x"},
		"missing pattern": {Name: "np-" + t.Name()},
		"bad status code": {Name: "sc-" + t.Name(), Pattern: "^/x", StatusCode: "abc"},
	}
	for name, in := range cases {
		resp := doAuthed(t, http.MethodPost, base, key, in)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: create = %d, want 400", name, resp.StatusCode)
		}
		resp.Body.Close()
	}
}
