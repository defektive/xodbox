package httpx

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/defektive/xodbox/pkg/model"
)

func TestSinkCRUDAndEvents(t *testing.T) {
	srv, _, u := adminTestServer(t)
	key, _, err := model.NewAPIKey(u.ID, "k", nil)
	if err != nil {
		t.Fatal(err)
	}
	base := srv.URL + "/api/sinks"

	// Create with an explicit slug + description.
	slug := uniqueName("sink")
	resp := doAuthed(t, http.MethodPost, base, key, createSinkRequest{Slug: slug, Description: "beacon test"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create sink = %d, want 201", resp.StatusCode)
	}
	var created sinkView
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.Slug != slug || created.Description != "beacon test" {
		t.Fatalf("created = %+v", created)
	}

	// Seed matching + non-matching interactions.
	model.DB().Create(&model.Interaction{Handler: "httpx", RequestTarget: "/" + slug + "/a"})
	model.DB().Create(&model.Interaction{Handler: "dns", RequestTarget: slug + ".oob.test."})
	model.DB().Create(&model.Interaction{Handler: "httpx", RequestTarget: "/nope"})

	// Detail returns the sink + its events (newest first) and a total.
	var detail sinkDetail
	if err := json.Unmarshal(getAuthed(t, base+"/"+slug, key), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Total != 2 || len(detail.Events) != 2 {
		t.Fatalf("detail total=%d events=%d, want 2/2", detail.Total, len(detail.Events))
	}
	if detail.Events[0].Handler != "dns" {
		t.Errorf("events[0].Handler = %q, want dns (newest first)", detail.Events[0].Handler)
	}

	// List includes it with the live event count.
	var list []sinkView
	if err := json.Unmarshal(getAuthed(t, base, key), &list); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range list {
		if s.Slug == slug {
			found = true
			if s.EventCount != 2 {
				t.Errorf("list event_count = %d, want 2", s.EventCount)
			}
		}
	}
	if !found {
		t.Error("created sink missing from list")
	}

	// Delete.
	del := doAuthed(t, http.MethodDelete, base+"/"+slug, key, nil)
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("delete sink = %d, want 204", del.StatusCode)
	}
	del.Body.Close()
	miss := doAuthed(t, http.MethodGet, base+"/"+slug, key, nil)
	if miss.StatusCode != http.StatusNotFound {
		t.Errorf("get after delete = %d, want 404", miss.StatusCode)
	}
	miss.Body.Close()
}

func TestSinkCreateValidation(t *testing.T) {
	srv, _, u := adminTestServer(t)
	key, _, _ := model.NewAPIKey(u.ID, "k", nil)
	base := srv.URL + "/api/sinks"

	// Invalid slug -> 400.
	bad := doAuthed(t, http.MethodPost, base, key, createSinkRequest{Slug: "bad slug!"})
	if bad.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid slug = %d, want 400", bad.StatusCode)
	}
	bad.Body.Close()

	// Empty slug -> generated (201).
	gen := doAuthed(t, http.MethodPost, base, key, createSinkRequest{Description: "auto"})
	if gen.StatusCode != http.StatusCreated {
		t.Fatalf("generated slug = %d, want 201", gen.StatusCode)
	}
	var v sinkView
	_ = json.NewDecoder(gen.Body).Decode(&v)
	gen.Body.Close()
	if !model.ValidSlug(v.Slug) {
		t.Errorf("generated slug %q invalid", v.Slug)
	}

	// Duplicate slug -> 400.
	dupResp := doAuthed(t, http.MethodPost, base, key, createSinkRequest{Slug: v.Slug})
	if dupResp.StatusCode != http.StatusBadRequest {
		t.Errorf("duplicate slug = %d, want 400", dupResp.StatusCode)
	}
	dupResp.Body.Close()
}
