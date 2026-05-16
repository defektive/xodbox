package httpx

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
)

func TestNewHandlerLoadsPayloadDir(t *testing.T) {
	payloads = nil
	t.Cleanup(func() { payloads = nil })
	if err := model.DB().Exec("DELETE FROM payloads").Error; err != nil {
		t.Fatalf("clear payloads: %v", err)
	}

	dir := t.TempDir()
	doc := `---
title: handler-dir-loader
pattern: ^/handler-dir-loader$
data:
  body: x
---
`
	if err := os.WriteFile(filepath.Join(dir, "p.md"), []byte(doc), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_ = NewHandler(map[string]string{
		"listener":    "127.0.0.1:0",
		"payload_dir": dir,
	})

	var p model.Payload
	if err := model.DB().Where("name = ?", "handler-dir-loader").First(&p).Error; err != nil {
		t.Fatalf("payload_dir entries should have been loaded into the DB: %v", err)
	}
}

func TestServerMuxStaticDirServesFiles(t *testing.T) {
	staticDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticDir, "hello.txt"), []byte("static hello"), 0o644); err != nil {
		t.Fatalf("seed static file: %v", err)
	}

	h := NewHandler(map[string]string{
		"listener":   "127.0.0.1:0",
		"static_dir": staticDir,
	}).(*Handler)
	h.app = &stubApp{data: map[string]string{}}
	h.dispatchChannel = make(chan types.InteractionEvent, 16)

	mux := h.serverMux()

	req := httptest.NewRequest(http.MethodGet, "/static/hello.txt", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != "static hello" {
		t.Errorf("body = %q, want %q", rr.Body.String(), "static hello")
	}
}

func TestServerMuxStaticDirAutoCreated(t *testing.T) {
	// Point static_dir at a non-existent path inside a tempdir so the
	// MkdirAll branch in serverMux is exercised.
	parent := t.TempDir()
	staticDir := filepath.Join(parent, "auto", "nested", "static")

	h := NewHandler(map[string]string{
		"listener":   "127.0.0.1:0",
		"static_dir": staticDir,
	}).(*Handler)
	h.app = &stubApp{data: map[string]string{}}
	h.dispatchChannel = make(chan types.InteractionEvent, 16)

	_ = h.serverMux()

	fi, err := os.Stat(staticDir)
	if err != nil {
		t.Fatalf("static dir should have been auto-created: %v", err)
	}
	if !fi.IsDir() {
		t.Errorf("static path %q is not a directory", staticDir)
	}
}
