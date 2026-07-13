package model

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// OIDCProfile is the subset of ID-token claims used to provision and update an
// OIDC-backed account. Subject is the stable identity key; the rest are used
// for display and role assignment.
type OIDCProfile struct {
	Subject           string
	Email             string
	PreferredUsername string
	Role              string
}

// UserForSubject resolves an OIDC subject to its user, or nil if none is
// linked. The empty subject never matches (that is the local-account value).
func UserForSubject(subject string) *User {
	if subject == "" {
		return nil
	}
	var u User
	if err := DB().Where("subject = ?", subject).First(&u).Error; err != nil {
		return nil
	}
	return &u
}

// UpsertOIDCUser provisions or refreshes an account for an OIDC identity. On
// first login it is created (with no password, so it can never authenticate by
// password); on subsequent logins its role is re-synced from the current claims
// so IdP group changes take effect. The account is matched solely by Subject —
// never by email/username — so a colliding email can't silently take over an
// existing local account.
func UpsertOIDCUser(p OIDCProfile) (*User, error) {
	if p.Subject == "" {
		return nil, errors.New("oidc: empty subject")
	}
	role := p.Role
	if role != RoleAdmin {
		role = RoleUser
	}

	if u := UserForSubject(p.Subject); u != nil {
		// Keep the role in sync with the latest claims.
		if u.Role != role {
			u.Role = role
			if err := DB().Model(u).Update("role", role).Error; err != nil {
				return nil, err
			}
		}
		return u, nil
	}

	u := &User{
		Username: availableUsername(oidcDisplayName(p)),
		Role:     role,
		Subject:  p.Subject,
	}
	if err := DB().Create(u).Error; err != nil {
		return nil, err
	}
	return u, nil
}

// oidcDisplayName picks the most human-friendly handle available from the
// profile, falling back to the subject so a username always exists.
func oidcDisplayName(p OIDCProfile) string {
	for _, cand := range []string{p.PreferredUsername, p.Email, p.Subject} {
		if n := normalizeUsername(cand); n != "" {
			return n
		}
	}
	return "oidc-user"
}

// availableUsername returns base, or base with a numeric suffix, ensuring the
// result is not already taken. Usernames carry a unique index, and two IdP
// users can legitimately share a preferred_username/email localpart, so a
// collision must not fail provisioning.
func availableUsername(base string) string {
	if _, err := UserByUsername(base); errors.Is(err, gorm.ErrRecordNotFound) {
		return base
	}
	for i := 2; i < 10000; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if _, err := UserByUsername(candidate); errors.Is(err, gorm.ErrRecordNotFound) {
			return candidate
		}
	}
	// Astronomically unlikely; fall back to a subject-derived handle.
	return base + "-" + strings.NewReplacer("/", "_", ":", "_").Replace(base)
}
