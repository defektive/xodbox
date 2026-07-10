package model

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMain points the model DB singleton at one stable temp database for the
// whole package. The singleton can't be re-pointed once loaded, and per-test
// t.TempDir() dirs are cleaned up mid-run, so a package-scoped DB is required.
// Tests use unique usernames (t.Name()) rather than per-test isolation.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "model-test-*")
	if err != nil {
		panic(err)
	}
	LoadDBWithOptions(DBOptions{Path: filepath.Join(dir, "test.db")})
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func setupAuthDB(t *testing.T) { t.Helper() }

func TestCreateUserAndAuthenticate(t *testing.T) {
	setupAuthDB(t)
	const pw = "correct horse battery"
	u, err := CreateUser(t.Name(), pw, RoleAdmin)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if !u.IsAdmin() {
		t.Error("user should be admin")
	}
	if u.PasswordHash == pw || u.PasswordHash == "" {
		t.Error("password must be stored hashed")
	}

	if got, err := Authenticate(t.Name(), pw); err != nil || got.ID != u.ID {
		t.Errorf("Authenticate(correct) = %v, %v", got, err)
	}
	if _, err := Authenticate(t.Name(), "wrong password here"); err != ErrInvalidCredentials {
		t.Errorf("Authenticate(wrong) err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := Authenticate("no-such-user-"+t.Name(), pw); err != ErrInvalidCredentials {
		t.Errorf("Authenticate(unknown) err = %v, want ErrInvalidCredentials", err)
	}
}

func TestWeakPasswordRejected(t *testing.T) {
	setupAuthDB(t)
	if _, err := CreateUser(t.Name(), "short", RoleUser); err != ErrWeakPassword {
		t.Errorf("err = %v, want ErrWeakPassword", err)
	}
}

func TestSetPasswordRotates(t *testing.T) {
	setupAuthDB(t)
	u, err := CreateUser(t.Name(), "initial password!!", RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.SetPassword("a brand new password"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if _, err := Authenticate(t.Name(), "initial password!!"); err == nil {
		t.Error("old password should no longer authenticate")
	}
	if _, err := Authenticate(t.Name(), "a brand new password"); err != nil {
		t.Errorf("new password should authenticate: %v", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	setupAuthDB(t)
	u, _ := CreateUser(t.Name(), "session password!!", RoleUser)

	token, err := NewSession(u.ID, DefaultSessionTTL, "agent", "10.0.0.1")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if got := UserForSession(token); got == nil || got.ID != u.ID {
		t.Fatalf("UserForSession = %v, want user %d", got, u.ID)
	}
	DeleteSession(token)
	if got := UserForSession(token); got != nil {
		t.Error("session should be revoked after DeleteSession")
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	setupAuthDB(t)
	u, _ := CreateUser(t.Name(), "expiry password!!", RoleUser)
	token, _ := NewSession(u.ID, -time.Second, "agent", "10.0.0.1")
	if got := UserForSession(token); got != nil {
		t.Error("expired session should not resolve to a user")
	}
}

func TestAPIKeyLifecycle(t *testing.T) {
	setupAuthDB(t)
	u, _ := CreateUser(t.Name(), "apikey password!!", RoleUser)

	full, rec, err := NewAPIKey(u.ID, "ci", nil)
	if err != nil {
		t.Fatalf("NewAPIKey: %v", err)
	}
	if rec.Hash == full || rec.Hash == "" {
		t.Error("API key must be stored hashed, not in cleartext")
	}
	if len(rec.Prefix) == 0 || rec.Prefix != full[:len(rec.Prefix)] {
		t.Errorf("prefix %q should be a leading slice of the key", rec.Prefix)
	}

	if got := UserForAPIKey(full); got == nil || got.ID != u.ID {
		t.Fatalf("UserForAPIKey(valid) = %v", got)
	}
	if got := UserForAPIKey(full + "tampered"); got != nil {
		t.Error("tampered key must not authenticate")
	}
	if got := UserForAPIKey("not-a-key"); got != nil {
		t.Error("malformed key must not authenticate")
	}

	if err := DeleteAPIKey(rec.ID, u.ID, false); err != nil {
		t.Fatalf("DeleteAPIKey: %v", err)
	}
	if got := UserForAPIKey(full); got != nil {
		t.Error("revoked key must not authenticate")
	}
}

func TestExpiredAPIKeyRejected(t *testing.T) {
	setupAuthDB(t)
	u, _ := CreateUser(t.Name(), "keyexpiry password", RoleUser)
	past := time.Now().Add(-time.Hour)
	full, _, _ := NewAPIKey(u.ID, "expired", &past)
	if got := UserForAPIKey(full); got != nil {
		t.Error("expired API key must not authenticate")
	}
}
