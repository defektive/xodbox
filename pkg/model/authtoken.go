package model

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// randomToken returns a cryptographically-random, URL-safe token encoding
// nBytes of entropy (32 bytes = 256 bits is the default for sessions/keys).
func randomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken returns the hex-encoded SHA-256 of a secret. Session tokens and
// API keys are stored only as this hash; the plaintext is shown to the user
// exactly once and never persisted.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
