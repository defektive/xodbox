package mdaas

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildReturnsCachedFileWithoutCompiling(t *testing.T) {
	dir := t.TempDir()

	// The output path Build constructs is:
	//   outDir/<os>/<arch>/<basename-of-program-without-ext>
	// for windows it appends .exe; for arm it appends the arm version.
	outDir := dir
	osTarget := TargetOSLinux
	archTarget := TargetArchAmd64
	program := "src/myprog.go"
	wantPath := filepath.Join(outDir, "linux", "amd64", "myprog")

	if err := os.MkdirAll(filepath.Dir(wantPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(wantPath, []byte("cached binary"), 0o755); err != nil {
		t.Fatalf("seed binary: %v", err)
	}

	got, err := Build(osTarget, archTarget, "", program, outDir, nil)
	if err != nil {
		t.Fatalf("Build err: %v", err)
	}
	if got != wantPath {
		t.Errorf("Build returned %q, want %q", got, wantPath)
	}
}

func TestBuildReturnsCachedWindowsExeName(t *testing.T) {
	dir := t.TempDir()
	wantPath := filepath.Join(dir, "windows", "amd64", "myprog.exe")
	if err := os.MkdirAll(filepath.Dir(wantPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(wantPath, []byte("x"), 0o755); err != nil {
		t.Fatalf("seed binary: %v", err)
	}

	got, err := Build(TargetOSWindows, TargetArchAmd64, "", "src/myprog.go", dir, nil)
	if err != nil {
		t.Fatalf("Build err: %v", err)
	}
	if got != wantPath {
		t.Errorf("Build returned %q, want %q", got, wantPath)
	}
}

func TestBuildReturnsCachedArmExeName(t *testing.T) {
	dir := t.TempDir()
	wantPath := filepath.Join(dir, "linux", "arm", "myprog7")
	if err := os.MkdirAll(filepath.Dir(wantPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(wantPath, []byte("x"), 0o755); err != nil {
		t.Fatalf("seed binary: %v", err)
	}

	got, err := Build(TargetOSLinux, TargetArchArm, "7", "src/myprog.go", dir, nil)
	if err != nil {
		t.Fatalf("Build err: %v", err)
	}
	if got != wantPath {
		t.Errorf("Build returned %q, want %q", got, wantPath)
	}
}
