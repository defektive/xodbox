package model

import "testing"

func TestCreateSinkGeneratesSlug(t *testing.T) {
	s, err := CreateSink("", "generated one")
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
	for _, bad := range []string{"ab", "has space", "no/slash", "bang!"} {
		if _, err := CreateSink(bad, ""); err != ErrInvalidSlug {
			t.Errorf("CreateSink(%q) err = %v, want ErrInvalidSlug", bad, err)
		}
	}

	first, err := CreateSink("", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateSink(first.Slug, ""); err != ErrSlugExists {
		t.Errorf("duplicate slug err = %v, want ErrSlugExists", err)
	}
}

func TestUpdateSinkDescription(t *testing.T) {
	s, err := CreateSink("", "old description")
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
	s, err := CreateSink("", "matcher")
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
	s, err := CreateSink("", "")
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
