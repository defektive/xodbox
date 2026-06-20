package httpx

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Build returns nil (and logs) when the OS cannot be resolved — it does not
// attempt to compile anything, so this stays hermetic.
func TestBuildUnknownOSReturnsNil(t *testing.T) {
	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/?o=nope&a=amd64&p=simple-ssh", ""))
	rr := httptest.NewRecorder()
	h := &Handler{name: "HTTPX"}

	if err := Build(rr, e, h); err != nil {
		t.Errorf("Build() with unknown OS = %v, want nil", err)
	}
}

// An unknown arch writes "error" and returns nil before any build occurs.
func TestBuildUnknownArchWritesError(t *testing.T) {
	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/?o=linux&a=bogusarch&p=simple-ssh", ""))
	rr := httptest.NewRecorder()
	h := &Handler{name: "HTTPX"}

	if err := Build(rr, e, h); err != nil {
		t.Errorf("Build() with unknown arch = %v, want nil", err)
	}
	if rr.Body.String() != "error" {
		t.Errorf("body = %q, want error", rr.Body.String())
	}
}

// An unknown program is rejected before invoking the toolchain; Build writes
// "error" and returns the program error.
func TestBuildUnknownProgramReturnsError(t *testing.T) {
	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/?o=linux&a=amd64&p=not-a-real-program", ""))
	rr := httptest.NewRecorder()
	h := &Handler{name: "HTTPX"}

	if err := Build(rr, e, h); err == nil {
		t.Error("Build() with unknown program should return an error")
	}
	if rr.Body.String() != "error" {
		t.Errorf("body = %q, want error", rr.Body.String())
	}
}

// sendFile streams an existing file to the writer.
func TestSendFileSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	want := []byte("artifact-contents")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	rr := httptest.NewRecorder()
	if err := sendFile(path, rr); err != nil {
		t.Fatalf("sendFile: %v", err)
	}
	if rr.Body.String() != string(want) {
		t.Errorf("body = %q, want %q", rr.Body.String(), want)
	}
}

// sendFile swallows a missing-file error (logs and returns nil) so a failed
// open does not surface as a handler error.
func TestSendFileMissingReturnsNil(t *testing.T) {
	rr := httptest.NewRecorder()
	if err := sendFile(filepath.Join(t.TempDir(), "does-not-exist"), rr); err != nil {
		t.Errorf("sendFile(missing) = %v, want nil", err)
	}
	if rr.Body.Len() != 0 {
		t.Errorf("missing file should write no body, got %q", rr.Body.String())
	}
}

// Content-Disposition / Content-Type attachment headers are NOT set on the
// error paths; confirm an early-return path leaves a clean recorder so we know
// Build short-circuits before header setup.
func TestBuildErrorPathSkipsAttachmentHeaders(t *testing.T) {
	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/?o=linux&a=bogusarch&p=simple-ssh", ""))
	rr := httptest.NewRecorder()
	_ = Build(rr, e, &Handler{name: "HTTPX"})

	if got := rr.Header().Get("Content-Disposition"); got != "" {
		t.Errorf("Content-Disposition should be unset on error path, got %q", got)
	}
}
