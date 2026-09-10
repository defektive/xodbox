package httpx

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestServerMuxStaticPathCustomPrefix(t *testing.T) {
	staticDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticDir, "hello.txt"), []byte("custom hello"), 0o644); err != nil {
		t.Fatalf("seed static file: %v", err)
	}

	h := NewHandler(map[string]string{
		"listener":    "127.0.0.1:0",
		"static_dir":  staticDir,
		"static_path": "assets",
	}).(*Handler)
	h.app = &stubApp{data: map[string]string{}}
	h.dispatchChannel = make(chan types.InteractionEvent, 16)

	if h.StaticPath != "/assets/" {
		t.Fatalf("StaticPath = %q, want %q", h.StaticPath, "/assets/")
	}

	mux := h.serverMux()

	req := httptest.NewRequest(http.MethodGet, "/assets/hello.txt", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != "custom hello" {
		t.Errorf("body = %q, want %q", rr.Body.String(), "custom hello")
	}
}

func TestServerMuxStaticPathRoot(t *testing.T) {
	staticDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticDir, "hello.txt"), []byte("root hello"), 0o644); err != nil {
		t.Fatalf("seed static file: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(staticDir, "sub"), 0o750); err != nil {
		t.Fatalf("seed static subdir: %v", err)
	}

	h := NewHandler(map[string]string{
		"listener":    "127.0.0.1:0",
		"static_dir":  staticDir,
		"static_path": "/",
	}).(*Handler)
	h.app = &stubApp{data: map[string]string{}}
	h.dispatchChannel = make(chan types.InteractionEvent, 32)

	mux := h.serverMux()

	// An existing file is served from disk.
	req := httptest.NewRequest(http.MethodGet, "/hello.txt", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != "root hello" {
		t.Errorf("body = %q, want %q", rr.Body.String(), "root hello")
	}
	// Dispatch is asynchronous; the event still has to arrive.
	select {
	case <-h.dispatchChannel:
	case <-time.After(time.Second):
		t.Error("root static request should still emit an InteractionEvent")
	}

	// Requests that do not resolve to a file fall through to payloads, and
	// directories never serve an index listing.
	for _, p := range []string{"/nope.txt", "/sub/", "/sub", "/"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.RemoteAddr = "127.0.0.1:1"
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Body.String() == "root hello" {
			t.Errorf("%s served the static file", p)
		}
		if strings.Contains(rr.Body.String(), "hello.txt") {
			t.Errorf("%s leaked a directory listing: %q", p, rr.Body.String())
		}
	}
}

func TestServeRootStaticRejectsTraversal(t *testing.T) {
	parent := t.TempDir()
	if err := os.WriteFile(filepath.Join(parent, "secret.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	staticDir := filepath.Join(parent, "static")
	if err := os.MkdirAll(staticDir, 0o750); err != nil {
		t.Fatalf("seed static dir: %v", err)
	}

	h := NewHandler(map[string]string{
		"listener":    "127.0.0.1:0",
		"static_dir":  staticDir,
		"static_path": "/",
	}).(*Handler)
	h.app = &stubApp{data: map[string]string{}}
	h.dispatchChannel = make(chan types.InteractionEvent, 16)
	_ = h.serverMux()

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.URL.Path = "/../secret.txt"
	rr := httptest.NewRecorder()

	if h.serveRootStatic(rr, req) {
		t.Fatalf("traversal outside static_dir should not be served: %q", rr.Body.String())
	}
}

func TestServerMuxStaticPathConflictDoesNotPanic(t *testing.T) {
	staticDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticDir, "hello.txt"), []byte("conflict"), 0o644); err != nil {
		t.Fatalf("seed static file: %v", err)
	}

	h := NewHandler(map[string]string{
		"listener":    "127.0.0.1:0",
		"static_dir":  staticDir,
		"static_path": EmbeddedMountPoint,
	}).(*Handler)
	h.app = &stubApp{data: map[string]string{}}
	h.dispatchChannel = make(chan types.InteractionEvent, 16)

	mux := h.serverMux()

	req := httptest.NewRequest(http.MethodGet, EmbeddedMountPoint+"hello.txt", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Body.String() == "conflict" {
		t.Error("static_dir should not shadow the embedded assets mount")
	}
}

func TestNormalizeMountPath(t *testing.T) {
	cases := map[string]string{
		"":        "",
		"/":       "/",
		"admin":   "/admin/",
		"/admin":  "/admin/",
		"admin/":  "/admin/",
		"/admin/": "/admin/",
		"a/b":     "/a/b/",
	}
	for in, want := range cases {
		if got := normalizeMountPath(in); got != want {
			t.Errorf("normalizeMountPath(%q) = %q, want %q", in, got, want)
		}
	}
}
