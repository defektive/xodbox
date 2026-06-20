package mdaas

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestGetInternalPrograms asserts the embedded filesystem exposes exactly the
// two payload program directories the rest of the package depends on.
func TestGetInternalPrograms(t *testing.T) {
	programs, err := GetInternalPrograms()
	if err != nil {
		t.Fatalf("GetInternalPrograms err: %v", err)
	}

	sort.Strings(programs)
	want := []string{"bind-shell", "simple-ssh"}
	if len(programs) != len(want) {
		t.Fatalf("GetInternalPrograms = %v, want %v", programs, want)
	}
	for i := range want {
		if programs[i] != want[i] {
			t.Errorf("program[%d] = %q, want %q", i, programs[i], want[i])
		}
	}
}

// TestMDaaSFSNonEmpty asserts the embedded source files exist and are
// non-empty (the build would still succeed with empty files, so verify the
// embed actually captured the payload sources).
func TestMDaaSFSNonEmpty(t *testing.T) {
	files := []string{
		"bind-shell/bind-shell.go",
		"simple-ssh/simple-ssh.go",
	}
	for _, f := range files {
		b, err := MDaaSFS.ReadFile(f)
		if err != nil {
			t.Errorf("ReadFile(%q) err: %v", f, err)
			continue
		}
		if len(b) == 0 {
			t.Errorf("embedded file %q is empty", f)
		}
	}
}

// TestCopyDirFromFS exercises SetupDirs -> CopyDirFromFS -> copyFileFromEmbeddedFS
// by materializing the embedded FS into a tempdir and verifying the resulting
// tree matches the embedded sources byte-for-byte.
func TestCopyDirFromFS(t *testing.T) {
	dest := t.TempDir()

	if err := SetupDirs(dest); err != nil {
		t.Fatalf("SetupDirs err: %v", err)
	}

	checks := []string{
		filepath.Join("bind-shell", "bind-shell.go"),
		filepath.Join("simple-ssh", "simple-ssh.go"),
	}
	for _, rel := range checks {
		gotPath := filepath.Join(dest, rel)
		got, err := os.ReadFile(gotPath)
		if err != nil {
			t.Errorf("expected copied file %q: %v", gotPath, err)
			continue
		}
		want, err := MDaaSFS.ReadFile(filepath.ToSlash(rel))
		if err != nil {
			t.Fatalf("read embedded %q: %v", rel, err)
		}
		if string(got) != string(want) {
			t.Errorf("copied file %q does not match embedded source", rel)
		}
	}
}

// TestCopyDirFromFSReadError verifies CopyDirFromFS surfaces an error when the
// source path does not exist in the embedded FS.
func TestCopyDirFromFSReadError(t *testing.T) {
	dest := t.TempDir()
	err := CopyDirFromFS("does-not-exist", dest, MDaaSFS)
	if err == nil {
		t.Error("CopyDirFromFS with bogus src: expected error, got nil")
	}
}
