package httpx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defektive/xodbox/pkg/model"
)

func TestHandleFileEventUpsertsPayload(t *testing.T) {
	payloads = nil
	t.Cleanup(func() { payloads = nil })
	if err := model.DB().Exec("DELETE FROM payloads").Error; err != nil {
		t.Fatalf("clear payloads: %v", err)
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "p.md")
	v1 := `---
title: watcher-payload
pattern: ^/watcher$
data:
  body: "v1"
---
`
	if err := os.WriteFile(file, []byte(v1), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// First write: payload should be created.
	modifiedFilesMu.Lock()
	modifiedFiles[file] = true
	modifiedFilesMu.Unlock()
	handleFileEvent()

	var loaded model.Payload
	if err := model.DB().Where("name = ?", "watcher-payload").First(&loaded).Error; err != nil {
		t.Fatalf("loading inserted payload: %v", err)
	}
	if !strings.Contains(loaded.Data, "v1") {
		t.Errorf("payload Data should contain v1 marker, got %q", loaded.Data)
	}

	// Modify the file and run handleFileEvent again — OnConflict should
	// update the existing row in place rather than panic.
	v2 := strings.Replace(v1, `"v1"`, `"v2"`, 1)
	if err := os.WriteFile(file, []byte(v2), 0o644); err != nil {
		t.Fatalf("rewrite file: %v", err)
	}
	modifiedFilesMu.Lock()
	modifiedFiles[file] = true
	modifiedFilesMu.Unlock()
	handleFileEvent()

	var reloaded model.Payload
	if err := model.DB().Where("name = ?", "watcher-payload").First(&reloaded).Error; err != nil {
		t.Fatalf("re-loading payload: %v", err)
	}
	if !strings.Contains(reloaded.Data, "v2") {
		t.Errorf("payload Data should contain v2 marker after re-load, got %q", reloaded.Data)
	}
	if reloaded.ID != loaded.ID {
		t.Errorf("OnConflict should have updated row in place; old ID %d, new ID %d", loaded.ID, reloaded.ID)
	}
}

func enqueueModified(path string) {
	modifiedFilesMu.Lock()
	defer modifiedFilesMu.Unlock()
	modifiedFiles[path] = true
}

func modifiedFilesContains(path string) bool {
	modifiedFilesMu.Lock()
	defer modifiedFilesMu.Unlock()
	_, present := modifiedFiles[path]
	return present
}

func TestHandleFileEventSkipsMissingFile(t *testing.T) {
	// Add a path that doesn't exist; handleFileEvent should log and
	// continue rather than panic.
	enqueueModified("/no/such/file.md")
	handleFileEvent()

	if modifiedFilesContains("/no/such/file.md") {
		t.Error("missing-file entry should still be drained from modifiedFiles")
	}
}

func TestHandleFileEventSkipsInvalidFrontmatter(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.md")
	if err := os.WriteFile(bad, []byte("---\npattern: /no-title\n---\n"), 0o644); err != nil {
		t.Fatalf("write bad file: %v", err)
	}

	enqueueModified(bad)
	handleFileEvent()

	if modifiedFilesContains(bad) {
		t.Error("invalid-frontmatter entry should be drained")
	}
}

// Note: a direct test of watchDir was previously here but its assignment
// to the package-global `watcher` raced with the unkillable goroutine
// spawned by NewHandler with payload_dir set. watchDir is now exercised
// indirectly through TestNewHandlerLoadsPayloadDir, which feeds the real
// watcher via filepath.Walk.
