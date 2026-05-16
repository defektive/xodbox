package mdaas

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestBuildInvokesGoToolchain exercises the toolchain-invocation path of
// Build (i.e. the case where the cached output does not exist). It writes
// a trivial go.mod + main.go into a tempdir and builds for the host OS
// and architecture so cross-compilation isn't required.
func TestBuildInvokesGoToolchain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping toolchain invocation in -short mode")
	}

	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"),
		[]byte("module probe\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	src := filepath.Join(srcDir, "main.go")
	if err := os.WriteFile(src,
		[]byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	outDir := t.TempDir()
	hostOS := TargetOS(runtime.GOOS)
	hostArch := TargetArch(runtime.GOARCH)

	got, err := Build(hostOS, hostArch, "", src, outDir, nil)
	if err != nil {
		t.Fatalf("Build err: %v", err)
	}

	// Expected layout: <outDir>/<os>/<arch>/<basename-without-ext>[.exe on win].
	wantBase := "main"
	if hostOS == "windows" {
		wantBase += ".exe"
	}
	wantPath := filepath.Join(outDir, string(hostOS), string(hostArch), wantBase)
	if got != wantPath {
		t.Errorf("Build returned %q, want %q", got, wantPath)
	}

	fi, err := os.Stat(got)
	if err != nil {
		t.Fatalf("stat built binary: %v", err)
	}
	if fi.Size() == 0 {
		t.Error("built binary is empty")
	}
}
