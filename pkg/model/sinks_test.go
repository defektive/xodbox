package model

import (
	"strings"
	"testing"
)

func TestDeleteSinkAllowsSlugReuse(t *testing.T) {
	s, err := CreateSink("", "first", false)
	if err != nil {
		t.Fatal(err)
	}
	slug := s.Slug
	if err := DeleteSink(slug); err != nil {
		t.Fatalf("DeleteSink: %v", err)
	}
	// Hard-delete must free the slug for reuse (a soft-delete would leave the
	// unique index occupied and reject this with ErrSlugExists).
	if _, err := CreateSink(slug, "second", false); err != nil {
		t.Errorf("recreating a deleted slug should succeed, got %v", err)
	}
}

func TestSinkEventsEscapesLikeWildcards(t *testing.T) {
	// A slug containing '_' (a LIKE single-char wildcard) must match literally,
	// not as a wildcard — consistent with the SSE stream's strings.Contains.
	slug := "sink_" + uniqueUsername() // e.g. "sink_u7"; ≥6 chars, contains '_'
	if _, err := CreateSink(slug, "", false); err != nil {
		t.Fatal(err)
	}

	// Literal occurrence → matches. Wildcard-only occurrence (the '_' position
	// replaced by another char) → must NOT match.
	DB().Create(&Interaction{Handler: "httpx", RequestTarget: "/x/" + slug})
	DB().Create(&Interaction{Handler: "httpx", RequestTarget: "/x/" + strings.Replace(slug, "_", "Z", 1)})

	if n := SinkEventCount(slug); n != 1 {
		t.Errorf("SinkEventCount = %d, want 1 (underscore must not act as a LIKE wildcard)", n)
	}
}

func TestCreateSinkGeneratesSlug(t *testing.T) {
	s, err := CreateSink("", "generated one", false)
	if err != nil {
		t.Fatalf("CreateSink: %v", err)
	}
	if !ValidSlug(s.Slug) {
		t.Errorf("generated slug %q is not valid", s.Slug)
	}
	if s.Description != "generated one" {
		t.Errorf("description = %q", s.Description)
	}
}

func TestCreateSinkRejectsInvalidAndDuplicateSlugs(t *testing.T) {
	// "short" is a valid charset but under the 6-char minimum.
	for _, bad := range []string{"ab", "short", "has space", "no/slash", "bang!"} {
		if _, err := CreateSink(bad, "", false); err != ErrInvalidSlug {
			t.Errorf("CreateSink(%q) err = %v, want ErrInvalidSlug", bad, err)
		}
	}

	first, err := CreateSink("", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateSink(first.Slug, "", false); err != ErrSlugExists {
		t.Errorf("duplicate slug err = %v, want ErrSlugExists", err)
	}
}

func TestUpdateSinkDescription(t *testing.T) {
	s, err := CreateSink("", "old description", false)
	if err != nil {
		t.Fatal(err)
	}

	updated, err := UpdateSinkDescription(s.Slug, "new description")
	if err != nil {
		t.Fatalf("UpdateSinkDescription: %v", err)
	}
	if updated.Description != "new description" {
		t.Errorf("returned description = %q, want %q", updated.Description, "new description")
	}
	// Persisted.
	got, err := SinkBySlug(s.Slug)
	if err != nil || got.Description != "new description" {
		t.Errorf("persisted description = %q (err %v)", got.Description, err)
	}
	// Slug is unchanged.
	if got.Slug != s.Slug {
		t.Errorf("slug changed: %q -> %q", s.Slug, got.Slug)
	}

	if _, err := UpdateSinkDescription("no-such-slug-here", "x"); err == nil {
		t.Error("updating an unknown slug should error")
	}
}

func TestSinkEventsMatchTargetAndHeaders(t *testing.T) {
	s, err := CreateSink("", "matcher", false)
	if err != nil {
		t.Fatal(err)
	}
	slug := s.Slug

	// Matches via request_target (HTTP path / DNS qname) and via the raw
	// headers dump (request line / Host); an unrelated row must not match.
	DB().Create(&Interaction{Handler: "httpx", RequestTarget: "/" + slug + "/beacon"})
	DB().Create(&Interaction{Handler: "dns", RequestTarget: slug + ".oob.example."})
	DB().Create(&Interaction{Handler: "httpx", RequestTarget: "/x",
		Headers: "GET /x?token=" + slug + " HTTP/1.1\r\nHost: h\r\n\r\n"})
	DB().Create(&Interaction{Handler: "httpx", RequestTarget: "/unrelated"})

	if n := SinkEventCount(slug); n != 3 {
		t.Fatalf("SinkEventCount = %d, want 3", n)
	}
	events := SinkEvents(slug, 0, 0)
	if len(events) != 3 {
		t.Fatalf("SinkEvents len = %d, want 3", len(events))
	}
	// Newest first: the header-match row was inserted last.
	if events[0].RequestTarget != "/x" {
		t.Errorf("events[0] target = %q, want /x (newest first)", events[0].RequestTarget)
	}
}

func TestDeleteSinkKeepsInteractions(t *testing.T) {
	s, err := CreateSink("", "", false)
	if err != nil {
		t.Fatal(err)
	}
	DB().Create(&Interaction{Handler: "httpx", RequestTarget: "/" + s.Slug})

	if err := DeleteSink(s.Slug); err != nil {
		t.Fatalf("DeleteSink: %v", err)
	}
	if _, err := SinkBySlug(s.Slug); err == nil {
		t.Error("sink should be gone after delete")
	}
	// The interaction it matched is untouched, so the events query still finds it.
	if n := SinkEventCount(s.Slug); n != 1 {
		t.Errorf("interactions should survive sink delete; count = %d, want 1", n)
	}
}
