package model

import (
	"fmt"
	"testing"
)

func TestUpsertOIDCUserCreatesAndLinks(t *testing.T) {
	sub := fmt.Sprintf("https://idp.example#%s", uniqueUsername())
	email := uniqueUsername() + "@example.com"

	u, err := UpsertOIDCUser(OIDCProfile{Subject: sub, Email: email, Role: RoleUser})
	if err != nil {
		t.Fatalf("UpsertOIDCUser: %v", err)
	}
	if u.PasswordHash != "" {
		t.Error("OIDC user must have no password hash")
	}
	if !u.IsOIDC() {
		t.Error("IsOIDC should be true")
	}
	if u.Username != email {
		t.Errorf("username = %q, want %q", u.Username, email)
	}

	// A password login must be impossible for an OIDC-provisioned account.
	if _, err := Authenticate(email, ""); err == nil {
		t.Error("OIDC account should not authenticate by password")
	}

	// Second login with the same subject returns the same account, not a dup.
	again, err := UpsertOIDCUser(OIDCProfile{Subject: sub, Email: email, Role: RoleUser})
	if err != nil {
		t.Fatalf("UpsertOIDCUser (repeat): %v", err)
	}
	if again.ID != u.ID {
		t.Errorf("re-login created a new user: %d != %d", again.ID, u.ID)
	}
}

func TestUpsertOIDCUserSyncsRole(t *testing.T) {
	sub := fmt.Sprintf("https://idp.example#%s", uniqueUsername())

	u, err := UpsertOIDCUser(OIDCProfile{Subject: sub, Role: RoleUser})
	if err != nil {
		t.Fatalf("UpsertOIDCUser: %v", err)
	}
	if u.IsAdmin() {
		t.Fatal("should start as non-admin")
	}

	promoted, err := UpsertOIDCUser(OIDCProfile{Subject: sub, Role: RoleAdmin})
	if err != nil {
		t.Fatalf("UpsertOIDCUser (promote): %v", err)
	}
	if promoted.ID != u.ID || !promoted.IsAdmin() {
		t.Errorf("role was not synced to admin on re-login: %+v", promoted)
	}

	// Reload from DB to confirm persistence.
	if reloaded, _ := UserByID(u.ID); reloaded == nil || !reloaded.IsAdmin() {
		t.Error("promoted role did not persist")
	}
}

func TestUpsertOIDCUserUniqueUsername(t *testing.T) {
	name := uniqueUsername()
	// A pre-existing account (local or OIDC) holds the preferred username.
	if _, err := CreateUser(name, "correct horse battery", RoleUser); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	sub := fmt.Sprintf("https://idp.example#%s", uniqueUsername())
	u, err := UpsertOIDCUser(OIDCProfile{Subject: sub, PreferredUsername: name, Role: RoleUser})
	if err != nil {
		t.Fatalf("UpsertOIDCUser: %v", err)
	}
	if u.Username == name {
		t.Error("username collision should have been suffixed")
	}
	if u.Username != name+"-2" {
		t.Errorf("username = %q, want %q", u.Username, name+"-2")
	}
}

func TestUpsertOIDCUserEmptySubject(t *testing.T) {
	if _, err := UpsertOIDCUser(OIDCProfile{Subject: "", Email: "x@example.com"}); err == nil {
		t.Error("empty subject should be rejected")
	}
}

func TestUserForSubject(t *testing.T) {
	if UserForSubject("") != nil {
		t.Error("empty subject must never match")
	}
	sub := fmt.Sprintf("https://idp.example#%s", uniqueUsername())
	u, err := UpsertOIDCUser(OIDCProfile{Subject: sub, Role: RoleUser})
	if err != nil {
		t.Fatalf("UpsertOIDCUser: %v", err)
	}
	got := UserForSubject(sub)
	if got == nil || got.ID != u.ID {
		t.Errorf("UserForSubject = %v, want id %d", got, u.ID)
	}
}
