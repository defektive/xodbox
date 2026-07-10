package model

import (
	"time"

	"gorm.io/gorm"
)

// DefaultSessionTTL is how long a login session stays valid.
const DefaultSessionTTL = 12 * time.Hour

// Session is a server-side browser session. Only the SHA-256 of the token is
// stored; the plaintext lives solely in the client's HttpOnly cookie.
type Session struct {
	gorm.Model
	UserID    uint      `gorm:"index"`
	TokenHash string    `gorm:"uniqueIndex"`
	ExpiresAt time.Time `gorm:"index"`
	UserAgent string
	RemoteIP  string
}

// NewSession creates a session for userID and returns the plaintext token
// (shown to the client once, stored only hashed).
func NewSession(userID uint, ttl time.Duration, userAgent, remoteIP string) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	s := &Session{
		UserID:    userID,
		TokenHash: hashToken(token),
		ExpiresAt: time.Now().Add(ttl),
		UserAgent: userAgent,
		RemoteIP:  remoteIP,
	}
	if err := DB().Create(s).Error; err != nil {
		return "", err
	}
	return token, nil
}

// UserForSession resolves a session token to its user, or nil if the token is
// unknown or expired. Expired sessions are pruned on access.
func UserForSession(token string) *User {
	if token == "" {
		return nil
	}
	var s Session
	if err := DB().Where("token_hash = ?", hashToken(token)).First(&s).Error; err != nil {
		return nil
	}
	if time.Now().After(s.ExpiresAt) {
		DB().Delete(&s)
		return nil
	}
	u, err := UserByID(s.UserID)
	if err != nil {
		return nil
	}
	return u
}

// DeleteSession revokes a single session by its token (logout).
func DeleteSession(token string) {
	if token == "" {
		return
	}
	DB().Where("token_hash = ?", hashToken(token)).Delete(&Session{})
}

// DeleteUserSessions revokes every session for a user (e.g. on password change).
func DeleteUserSessions(userID uint) {
	DB().Where("user_id = ?", userID).Delete(&Session{})
}

// PurgeExpiredSessions removes all sessions past their expiry.
func PurgeExpiredSessions() {
	DB().Where("expires_at < ?", time.Now()).Delete(&Session{})
}
