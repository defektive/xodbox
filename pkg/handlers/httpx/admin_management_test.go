package httpx

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/defektive/xodbox/pkg/model"
)

func TestUsersRequireAdmin(t *testing.T) {
	srv, _, _ := adminTestServer(t)

	// A non-admin user's key must be rejected by admin-only routes.
	nonAdmin, err := model.CreateUser(uniqueName("plebe"), testPassword, model.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	key, _, _ := model.NewAPIKey(nonAdmin.ID, "k", nil)

	resp := doAuthed(t, http.MethodGet, srv.URL+"/api/users", key, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin GET /api/users = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestUserManagement(t *testing.T) {
	srv, _, admin := adminTestServer(t) // admin user
	adminKey, _, _ := model.NewAPIKey(admin.ID, "k", nil)

	// Create a user.
	resp := doAuthed(t, http.MethodPost, srv.URL+"/api/users", adminKey, createUserRequest{
		Username: uniqueName("newbie"), Password: "a-strong-password!!", Role: "user",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user = %d, want 201", resp.StatusCode)
	}
	var created userView
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()

	// Cannot delete your own account.
	self := doAuthed(t, http.MethodDelete, fmt.Sprintf("%s/api/users/%d", srv.URL, admin.ID), adminKey, nil)
	if self.StatusCode != http.StatusBadRequest {
		t.Errorf("self-delete = %d, want 400", self.StatusCode)
	}
	self.Body.Close()

	// Delete the created user.
	del := doAuthed(t, http.MethodDelete, fmt.Sprintf("%s/api/users/%d", srv.URL, created.ID), adminKey, nil)
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("delete user = %d, want 204", del.StatusCode)
	}
	del.Body.Close()
	if _, err := model.UserByID(created.ID); err == nil {
		t.Error("user should be deleted")
	}
}

func TestAccountPasswordChange(t *testing.T) {
	srv, _, u := adminTestServer(t)
	key, _, _ := model.NewAPIKey(u.ID, "k", nil)

	// Wrong current password is rejected.
	bad := doAuthed(t, http.MethodPost, srv.URL+"/api/account/password", key,
		changePasswordRequest{Current: "not the password", New: "brand-new-password"})
	if bad.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong current = %d, want 401", bad.StatusCode)
	}
	bad.Body.Close()

	// Correct current password rotates it.
	ok := doAuthed(t, http.MethodPost, srv.URL+"/api/account/password", key,
		changePasswordRequest{Current: testPassword, New: "brand-new-password"})
	if ok.StatusCode != http.StatusNoContent {
		t.Fatalf("change password = %d, want 204", ok.StatusCode)
	}
	ok.Body.Close()

	if _, err := model.Authenticate(u.Username, testPassword); err == nil {
		t.Error("old password should no longer work")
	}
	if _, err := model.Authenticate(u.Username, "brand-new-password"); err != nil {
		t.Error("new password should work")
	}
}

func TestAPIKeyManagement(t *testing.T) {
	srv, _, u := adminTestServer(t)
	bootKey, _, _ := model.NewAPIKey(u.ID, "boot", nil)

	// Create a key — the plaintext is returned once.
	resp := doAuthed(t, http.MethodPost, srv.URL+"/api/apikeys", bootKey, createAPIKeyRequest{Name: "ci"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create key = %d, want 201", resp.StatusCode)
	}
	var created struct {
		apiKeyView
		Key string `json:"key"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.Key == "" || created.ID == 0 {
		t.Fatal("create key response missing key/id")
	}

	// The returned key authenticates.
	if model.UserForAPIKey(created.Key) == nil {
		t.Error("issued key should authenticate")
	}

	// Delete it; it should stop working.
	del := doAuthed(t, http.MethodDelete, fmt.Sprintf("%s/api/apikeys/%d", srv.URL, created.ID), bootKey, nil)
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("delete key = %d, want 204", del.StatusCode)
	}
	del.Body.Close()
	if model.UserForAPIKey(created.Key) != nil {
		t.Error("deleted key should not authenticate")
	}
}
