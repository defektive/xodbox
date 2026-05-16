package httpx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/fsnotify/fsnotify"
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
	modifiedFiles[file] = true
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
	modifiedFiles[file] = true
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

func TestHandleFileEventSkipsMissingFile(t *testing.T) {
	// Add a path that doesn't exist; handleFileEvent should log and
	// continue rather than panic.
	modifiedFiles["/no/such/file.md"] = true
	handleFileEvent()

	if _, present := modifiedFiles["/no/such/file.md"]; present {
		t.Error("missing-file entry should still be drained from modifiedFiles")
	}
}

func TestHandleFileEventSkipsInvalidFrontmatter(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.md")
	if err := os.WriteFile(bad, []byte("---\npattern: /no-title\n---\n"), 0o644); err != nil {
		t.Fatalf("write bad file: %v", err)
	}

	modifiedFiles[bad] = true
	handleFileEvent()

	if _, present := modifiedFiles[bad]; present {
		t.Error("invalid-frontmatter entry should be drained")
	}
}

func TestWatchDirAddsDirectoriesOnly(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "sub")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("hi"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// watchDir refers to the package-global watcher; set up one for this test.
	prev := watcher
	w, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	watcher = w
	t.Cleanup(func() {
		w.Close()
		watcher = prev
	})

	fi, err := os.Stat(subdir)
	if err != nil {
		t.Fatalf("stat subdir: %v", err)
	}
	if err := watchDir(subdir, fi, nil); err != nil {
		t.Errorf("watchDir(dir) err = %v", err)
	}

	ffi, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if err := watchDir(file, ffi, nil); err != nil {
		t.Errorf("watchDir(file) err = %v, want nil (files should be a no-op)", err)
	}
}
