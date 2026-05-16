package ftp

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
)

func openOSFile(t *testing.T, name, content string) afero.File {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	osFs := afero.NewOsFs()
	f, err := osFs.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	return f
}

func TestTestFileCloseNormal(t *testing.T) {
	tf := &testFile{File: openOSFile(t, "fine.txt", "ok")}
	if err := tf.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}

func TestTestFileCloseFailureByName(t *testing.T) {
	tf := &testFile{File: openOSFile(t, "please-fail-to-close.txt", "x")}
	if err := tf.Close(); !errors.Is(err, errFailClose) {
		t.Errorf("Close() = %v, want errFailClose", err)
	}
}

func TestTestFileSeekNormal(t *testing.T) {
	tf := &testFile{File: openOSFile(t, "regular.txt", "hello world")}
	defer tf.Close()

	got, err := tf.Seek(6, 0)
	if err != nil {
		t.Fatalf("Seek err: %v", err)
	}
	if got != 6 {
		t.Errorf("Seek pos = %d, want 6", got)
	}
}

func TestTestFileSeekFailureByName(t *testing.T) {
	tf := &testFile{File: openOSFile(t, "fail-to-seek.txt", "x")}
	defer tf.Close()

	if _, err := tf.Seek(0, 0); !errors.Is(err, errFailSeek) {
		t.Errorf("Seek = %v, want errFailSeek", err)
	}
}

func TestTestFileTransferError(t *testing.T) {
	tf := &testFile{File: openOSFile(t, "x.txt", "x")}
	defer tf.Close()

	want := errors.New("transfer borked")
	tf.TransferError(want)
	if !errors.Is(tf.errTransfer, want) {
		t.Errorf("errTransfer = %v, want %v", tf.errTransfer, want)
	}
}
