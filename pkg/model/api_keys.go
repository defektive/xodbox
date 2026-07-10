package model

import (
	"crypto/subtle"
	"strings"
	"time"

	"gorm.io/gorm"
)

// apiKeyPrefix labels every issued key; keyLookupLen is how many leading
// characters (prefix + random) are stored in cleartext as a non-secret lookup
// handle so verification can fetch a single row then constant-time compare.
const (
	apiKeyPrefix = "xdbx_"
	keyLookupLen = len(apiKeyPrefix) + 8
)

// APIKey is a bearer credential for programmatic access. Only the SHA-256 of
// the full key is stored; Prefix is a non-secret display/lookup handle.
type APIKey struct {
	gorm.Model
	UserID     uint       `json:"user_id" gorm:"index"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix" gorm:"index"`
	Hash       string     `json:"-"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
}

// NewAPIKey issues a key for userID and returns the plaintext key (shown once)
// plus the stored record. expiresAt is optional (nil = never expires).
func NewAPIKey(userID uint, name string, expiresAt *time.Time) (string, *APIKey, error) {
	secret, err := randomToken(32)
	if err != nil {
		return "", nil, err
	}
	full := apiKeyPrefix + secret
	k := &APIKey{
		UserID:    userID,
		Name:      name,
		Prefix:    full[:keyLookupLen],
		Hash:      hashToken(full),
		ExpiresAt: expiresAt,
	}
	if err := DB().Create(k).Error; err != nil {
		return "", nil, err
	}
	return full, k, nil
}

// UserForAPIKey verifies a bearer key and returns its user, or nil. It looks
// the row up by the non-secret prefix, then compares the stored hash to the
// presented key's hash in constant time. LastUsedAt is updated on success.
func UserForAPIKey(full string) *User {
	if !strings.HasPrefix(full, apiKeyPrefix) || len(full) < keyLookupLen {
		return nil
	}
	var k APIKey
	if err := DB().Where("prefix = ?", full[:keyLookupLen]).First(&k).Error; err != nil {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(k.Hash), []byte(hashToken(full))) != 1 {
		return nil
	}
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return nil
	}
	now := time.Now()
	DB().Model(&k).Update("last_used_at", &now)
	u, err := UserByID(k.UserID)
	if err != nil {
		return nil
	}
	return u
}

func ListAPIKeys(userID uint) []APIKey {
	var keys []APIKey
	DB().Where("user_id = ?", userID).Order("created_at desc").Find(&keys)
	return keys
}

// DeleteAPIKey revokes a key. When requesterIsAdmin is false the key must
// belong to requesterID.
func DeleteAPIKey(id, requesterID uint, requesterIsAdmin bool) error {
	q := DB().Where("id = ?", id)
	if !requesterIsAdmin {
		q = q.Where("user_id = ?", requesterID)
	}
	return q.Delete(&APIKey{}).Error
}
