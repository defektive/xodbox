package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defektive/xodbox/pkg/model"
)

// TestMain points the model DB singleton at one stable temp database for the
// whole cmd package. Per-test t.TempDir() DBs are cleaned up mid-run and the
// singleton can't be re-pointed, so a package-scoped DB is required.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cmd-test-*")
	if err != nil {
		panic(err)
	}
	model.LoadDBWithOptions(model.DBOptions{Path: filepath.Join(dir, "test.db")})
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func TestUserAddAndRemove(t *testing.T) {
	model.LoadDBWithOptions(model.DBOptions{Path: filepath.Join(t.TempDir(), "user-cli.db")})

	userPassword = "a-strong-test-password"
	userRoleAdmin = true
	t.Cleanup(func() { userPassword = ""; userRoleAdmin = false })

	if err := userAddCmd.RunE(userAddCmd, []string{"cli-admin"}); err != nil {
		t.Fatalf("user add: %v", err)
	}
	u, err := model.UserByUsername("cli-admin")
	if err != nil {
		t.Fatalf("user not created: %v", err)
	}
	if !u.IsAdmin() {
		t.Error("--admin should create an admin user")
	}

	if err := userRmCmd.RunE(userRmCmd, []string{"cli-admin"}); err != nil {
		t.Fatalf("user rm: %v", err)
	}
	if _, err := model.UserByUsername("cli-admin"); err == nil {
		t.Error("user should be removed")
	}
}

func TestGeneratePasswordMeetsPolicy(t *testing.T) {
	p, err := generatePassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(p) < 12 {
		t.Errorf("generated password too short: %d chars", len(p))
	}
}
