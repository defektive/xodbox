package httpx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defektive/xodbox/pkg/model"
)

func TestGetPayloadsFromFrontmatterValid(t *testing.T) {
	doc := `---
title: my-payload
description: a description
pattern: ^/api/.*$
weight: 5
is_final: true
internal_function: inspect
data:
  body: "hello"
  status_code: "200"
---
trailing content
`
	p, err := getPayloadsFromFrontmatter(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if p.Name != "my-payload" {
		t.Errorf("Name = %q, want my-payload", p.Name)
	}
	if p.Description != "a description" {
		t.Errorf("Description = %q", p.Description)
	}
	if p.Pattern != "^/api/.*$" {
		t.Errorf("Pattern = %q", p.Pattern)
	}
	if p.SortOrder != 5 {
		t.Errorf("SortOrder = %d, want 5", p.SortOrder)
	}
	if !p.IsFinal {
		t.Error("IsFinal should be true")
	}
	if p.InternalFunction != "inspect" {
		t.Errorf("InternalFunction = %q", p.InternalFunction)
	}
	if p.Data.Body != "hello" {
		t.Errorf("Data.Body = %q, want hello", p.Data.Body)
	}
}

func TestGetPayloadsFromFrontmatterMissingTitle(t *testing.T) {
	doc := `---
pattern: /thing
---
`
	if _, err := getPayloadsFromFrontmatter(strings.NewReader(doc)); err == nil {
		t.Error("expected error for missing title")
	}
}

func TestGetPayloadsFromFrontmatterMissingPattern(t *testing.T) {
	doc := `---
title: thing
---
`
	if _, err := getPayloadsFromFrontmatter(strings.NewReader(doc)); err == nil {
		t.Error("expected error for missing pattern")
	}
}

func TestSeedPayloadToHTTPPayload(t *testing.T) {
	body := "body"
	sp := &SeedPayload{
		Title:            "x",
		Description:      "d",
		Pattern:          "p",
		Weight:           3,
		IsFinal:          true,
		InternalFunction: "inspect",
		Data:             &PayloadData{Body: body},
	}

	p := sp.ToHTTPPayload()
	if p.Name != "x" || p.Pattern != "p" || p.SortOrder != 3 || !p.IsFinal ||
		p.InternalFunction != "inspect" {
		t.Errorf("ToHTTPPayload mapped wrong: %+v", p)
	}
	if p.Data.Body != body {
		t.Errorf("Data not copied: %q", p.Data.Body)
	}
}

func TestCreatePayloadsFromDir(t *testing.T) {
	// Reset state so this test is independent of others.
	payloads = nil
	t.Cleanup(func() { payloads = nil })
	if err := model.DB().Exec("DELETE FROM payloads").Error; err != nil {
		t.Fatalf("clear payloads: %v", err)
	}

	dir := t.TempDir()
	good := `---
title: dir-seed-{{NAME}}
pattern: ^/dir-seed-{{NAME}}$
data:
  body: hi
---
`
	if err := os.WriteFile(filepath.Join(dir, "a.md"),
		[]byte(strings.ReplaceAll(good, "{{NAME}}", "a")), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.md"),
		[]byte(strings.ReplaceAll(good, "{{NAME}}", "b")), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	// invalid file (no title): should be skipped without aborting load
	if err := os.WriteFile(filepath.Join(dir, "bad.md"),
		[]byte("---\npattern: ^/bad$\n---\n"), 0o644); err != nil {
		t.Fatalf("write bad file: %v", err)
	}

	CreatePayloadsFromDir(dir, model.DB())

	got := SortedPayloads()
	names := make(map[string]bool)
	for _, p := range got {
		names[p.Name] = true
	}
	if !names["dir-seed-a"] || !names["dir-seed-b"] {
		t.Errorf("expected dir-seed-a and dir-seed-b, got %+v", names)
	}
}
