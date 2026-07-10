package model

import (
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Roles. Admin users may manage other users and any API key; regular users
// manage only their own account and keys.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

var (
	// ErrInvalidCredentials is returned by Authenticate for any failure so
	// callers can't distinguish "no such user" from "wrong password".
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrWeakPassword       = errors.New("password must be at least 12 characters")
)

// User is an admin-console account. PasswordHash is a bcrypt hash and is never
// serialized.
type User struct {
	gorm.Model
	Username     string `json:"username" gorm:"uniqueIndex"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"`
}

// IsAdmin reports whether the user has the admin role.
func (u *User) IsAdmin() bool { return u.Role == RoleAdmin }

// CreateUser creates a user with a bcrypt-hashed password. Usernames are
// normalized (trimmed, lower-cased) and passwords have a minimum length.
func CreateUser(username, password, role string) (*User, error) {
	username = normalizeUsername(username)
	if username == "" {
		return nil, errors.New("username required")
	}
	if len(password) < 12 {
		return nil, ErrWeakPassword
	}
	if role != RoleAdmin {
		role = RoleUser
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	u := &User{Username: username, PasswordHash: string(hash), Role: role}
	if err := DB().Create(u).Error; err != nil {
		return nil, err
	}
	return u, nil
}

// Authenticate verifies a username/password and returns the user. It always
// runs a bcrypt comparison (against a dummy hash when the user is missing) so
// response timing does not reveal whether the username exists.
func Authenticate(username, password string) (*User, error) {
	u, err := UserByUsername(username)
	if err != nil {
		// Compare against a fixed hash to keep timing uniform.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return nil, ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return nil, ErrInvalidCredentials
	}
	return u, nil
}

// dummyHash is a valid bcrypt hash of a random value, used to equalize timing
// for unknown usernames.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("xodbox-timing-equalizer"), bcrypt.DefaultCost)

// SetPassword updates the user's password (bcrypt).
func (u *User) SetPassword(password string) error {
	if len(password) < 12 {
		return ErrWeakPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hash)
	return DB().Model(u).Update("password_hash", u.PasswordHash).Error
}

func UserByUsername(username string) (*User, error) {
	var u User
	if err := DB().Where("username = ?", normalizeUsername(username)).First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

func UserByID(id uint) (*User, error) {
	var u User
	if err := DB().First(&u, id).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

func ListUsers() []User {
	var users []User
	DB().Order("username asc").Find(&users)
	return users
}

func CountUsers() int64 {
	var n int64
	DB().Model(&User{}).Count(&n)
	return n
}

// CountAdmins returns the number of admin users, used to prevent removing or
// demoting the last administrator (which would lock everyone out).
func CountAdmins() int64 {
	var n int64
	DB().Model(&User{}).Where("role = ?", RoleAdmin).Count(&n)
	return n
}

// DeleteUser removes a user and cascades their sessions and API keys.
func DeleteUser(id uint) error {
	DeleteUserSessions(id)
	DB().Where("user_id = ?", id).Delete(&APIKey{})
	return DB().Delete(&User{}, id).Error
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}
