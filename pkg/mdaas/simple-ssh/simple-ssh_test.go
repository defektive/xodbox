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

	if got == "/bin/sh" {
		return
	}

	resolved, err := exec.LookPath(got)
	if err != nil {
		t.Errorf("getCommandToExecute returned %q which is not in PATH: %v", got, err)
	}
	if resolved == "" {
		t.Errorf("getCommandToExecute returned %q which does not resolve", got)
	}
}

// TestGetCommandToExecuteDeterministic ensures the helper is deterministic for
// a fixed environment.
func TestGetCommandToExecuteDeterministic(t *testing.T) {
	first := getCommandToExecute()
	for i := 0; i < 5; i++ {
		if got := getCommandToExecute(); got != first {
			t.Fatalf("getCommandToExecute not deterministic: got %q then %q", first, got)
		}
	}
}

// TestPackageDefaults documents the build-time-overridable defaults. The mdaas
// builder overrides these via -ldflags, so a change here should be intentional.
func TestPackageDefaults(t *testing.T) {
	if listener != ":2222" {
		t.Errorf("default listener = %q, want %q", listener, ":2222")
	}
	if allowedCIDR != "0.0.0.0/0" {
		t.Errorf("default allowedCIDR = %q, want %q", allowedCIDR, "0.0.0.0/0")
	}
	if logLevel != "NONE" {
		t.Errorf("default logLevel = %q, want %q", logLevel, "NONE")
	}
}

// TestLogLevelsMap asserts the log-level lookup table maps the standard slog
// level strings to their values, with "NONE" as a disabling sentinel.
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

// TestSetWinsizeNoPanic exercises setWinsize (currently a no-op) to ensure it
// does not panic when handed a real *os.File.
func TestSetWinsizeNoPanic(t *testing.T) {
	setWinsize(os.Stdout, 80, 24)
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
		t.Fatalf("go build of simple-ssh failed: %v\n%s", err, out)
	}
}
