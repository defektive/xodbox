package ftp

import (
	"errors"
	"testing"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"
)

func TestMessageDriverPostAuthMessage(t *testing.T) {
	d := &MesssageDriver{}

	if got := d.PostAuthMessage(nil, "", nil); got != "Welcome to the FTP Server" {
		t.Errorf("success message = %q, want welcome message", got)
	}

	if got := d.PostAuthMessage(nil, "", errors.New("nope")); got != "You are not welcome here" {
		t.Errorf("failure message = %q, want rejection message", got)
	}
}

func TestMessageDriverQuitMessage(t *testing.T) {
	d := &MesssageDriver{}
	if got := d.QuitMessage(); got != "Sayonara, bye bye!" {
		t.Errorf("QuitMessage = %q, want %q", got, "Sayonara, bye bye!")
	}
}

func TestSimpleServerDriverGetSettings(t *testing.T) {
	want := &ftpserver.Settings{ListenAddr: "127.0.0.1:0"}
	d := &SimpleServerDriver{Settings: want}

	got, err := d.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings err: %v", err)
	}
	if got != want {
		t.Error("GetSettings should return the configured Settings pointer")
	}
}

func TestSimpleServerDriverGetTLSConfigDisabled(t *testing.T) {
	d := &SimpleServerDriver{TLS: false}
	cfg, err := d.GetTLSConfig()
	if !errors.Is(err, errNoTLS) {
		t.Errorf("err = %v, want errNoTLS", err)
	}
	if cfg != nil {
		t.Error("config should be nil when TLS disabled")
	}
}

func TestSimpleServerDriverGetTLSConfigEnabled(t *testing.T) {
	d := &SimpleServerDriver{TLS: true}
	cfg, err := d.GetTLSConfig()
	if err != nil {
		t.Fatalf("GetTLSConfig err: %v", err)
	}
	if cfg == nil || len(cfg.Certificates) == 0 {
		t.Error("expected at least one certificate when TLS enabled")
	}
}

func TestSimpleServerDriverWrapPassiveListener(t *testing.T) {
	d := &SimpleServerDriver{}
	if _, err := d.WrapPassiveListener(nil); err != nil {
		t.Errorf("unexpected err with nil-listener pass-through: %v", err)
	}

	failErr := errors.New("boom")
	d2 := &SimpleServerDriver{errPassiveListener: failErr}
	if _, err := d2.WrapPassiveListener(nil); !errors.Is(err, failErr) {
		t.Errorf("err = %v, want %v", err, failErr)
	}
}

func newMemClientDriver(user *AuthUser) (*SimpleClientDriver, afero.Fs) {
	fs := afero.NewMemMapFs()
	return &SimpleClientDriver{
		User: user,
		Fs:   fs,
	}, fs
}

func TestAllocateSpaceSmallOK(t *testing.T) {
	cd, _ := newMemClientDriver(&AuthUser{})
	if err := cd.AllocateSpace(1024); err != nil {
		t.Errorf("small allocation rejected: %v", err)
	}
}

func TestAllocateSpaceTooMuch(t *testing.T) {
	cd, _ := newMemClientDriver(&AuthUser{})
	if err := cd.AllocateSpace(10 * 1024 * 1024); !errors.Is(err, errTooMuchSpaceRequested) {
		t.Errorf("err = %v, want errTooMuchSpaceRequested", err)
	}
}

func TestGetAvailableSpaceMagicPath(t *testing.T) {
	cd, _ := newMemClientDriver(&AuthUser{})
	got, err := cd.GetAvailableSpace("/420")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != 420 {
		t.Errorf("size = %d, want 420", got)
	}
}

func TestGetAvailableSpaceDenied(t *testing.T) {
	cd, _ := newMemClientDriver(&AuthUser{})
	if _, err := cd.GetAvailableSpace("/anywhere"); !errors.Is(err, errAvblNotPermitted) {
		t.Errorf("err = %v, want errAvblNotPermitted", err)
	}
}

func TestChownInvalidUser(t *testing.T) {
	cd, _ := newMemClientDriver(&AuthUser{UserID: 1000, GroupID: 1000})
	if err := cd.Chown("anything", 9999, 1000); !errors.Is(err, errInvalidChownUser) {
		t.Errorf("err = %v, want errInvalidChownUser", err)
	}
}

func TestChownInvalidGroup(t *testing.T) {
	cd, _ := newMemClientDriver(&AuthUser{UserID: 1000, GroupID: 1000})
	if err := cd.Chown("anything", 1000, 9999); !errors.Is(err, errInvalidChownGroup) {
		t.Errorf("err = %v, want errInvalidChownGroup", err)
	}
}

func TestChownMatchingIDsStatsFile(t *testing.T) {
	cd, fs := newMemClientDriver(&AuthUser{UserID: 1000, GroupID: 1000})
	// matching IDs proceed to fs.Stat — file missing → error from fs
	if err := cd.Chown("/missing", 1000, 1000); err == nil {
		t.Error("expected stat error for missing file")
	}

	// Create the file and try again.
	if err := afero.WriteFile(fs, "/exists", []byte("hi"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := cd.Chown("/exists", 1000, 1000); err != nil {
		t.Errorf("expected nil err for existing file, got %v", err)
	}
}

func TestChownRootUIDBypassesCheck(t *testing.T) {
	cd, fs := newMemClientDriver(&AuthUser{UserID: 1000, GroupID: 1000})
	if err := afero.WriteFile(fs, "/exists", []byte("hi"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	// uid=0 is allowed regardless of user.UserID
	if err := cd.Chown("/exists", 0, 1000); err != nil {
		t.Errorf("uid=0 should bypass user check: %v", err)
	}
	// gid=0 is allowed regardless of user.GroupID
	if err := cd.Chown("/exists", 1000, 0); err != nil {
		t.Errorf("gid=0 should bypass group check: %v", err)
	}
}

func TestSymlinkNotImplementedOnMemFs(t *testing.T) {
	cd, _ := newMemClientDriver(&AuthUser{})
	// MemMapFs does not implement afero.Linker, so we get the not-implemented error.
	if err := cd.Symlink("a", "b"); !errors.Is(err, errSymlinkNotImplemented) {
		t.Errorf("err = %v, want errSymlinkNotImplemented", err)
	}
}

func TestRenameFile(t *testing.T) {
	cd, fs := newMemClientDriver(&AuthUser{})
	if err := afero.WriteFile(fs, "/from", []byte("x"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := cd.Rename("/from", "/to"); err != nil {
		t.Fatalf("Rename err: %v", err)
	}
	if _, err := fs.Stat("/to"); err != nil {
		t.Errorf("destination should exist after rename: %v", err)
	}
}

func TestOpenFileWrapsAsTestFile(t *testing.T) {
	cd, fs := newMemClientDriver(&AuthUser{})
	if err := afero.WriteFile(fs, "/x", []byte("hi"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	f, err := cd.OpenFile("/x", 0, 0o644)
	if err != nil {
		t.Fatalf("OpenFile err: %v", err)
	}
	defer f.Close()

	if _, ok := f.(*testFile); !ok {
		t.Errorf("OpenFile returned %T, want *testFile", f)
	}
}

func TestOpenWrapsAsTestFile(t *testing.T) {
	cd, fs := newMemClientDriver(&AuthUser{})
	if err := afero.WriteFile(fs, "/y", []byte("hi"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	f, err := cd.Open("/y")
	if err != nil {
		t.Fatalf("Open err: %v", err)
	}
	defer f.Close()

	if _, ok := f.(*testFile); !ok {
		t.Errorf("Open returned %T, want *testFile", f)
	}
}

func TestNewSimpleClientDriverWires(t *testing.T) {
	h := &Handler{name: "FTP"}
	fs := afero.NewMemMapFs()
	srv := &SimpleServerDriver{Handler: h, fs: fs}
	user := &AuthUser{Username: "x"}

	cd := NewSimpleClientDriver(nil, srv, user)
	if cd.Handler != h {
		t.Error("Handler not wired")
	}
	if cd.User != user {
		t.Error("User not wired")
	}
	if cd.Fs != fs {
		t.Error("Fs not wired")
	}
}
