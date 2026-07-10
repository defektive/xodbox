package model

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"regexp"
	"strings"

	"gorm.io/gorm"
)

// Sink is a named, described slug an operator uses to correlate out-of-band
// interactions. The slug is embedded in a payload (a URL path, a DNS label, a
// query value, …); any interaction whose target or raw request contains the
// slug is attributed to the sink. Sinks are a saved, described view over
// interactions — creating one does not change what the honeypot captures (every
// path/name is already recorded), it just labels and groups the hits.
type Sink struct {
	gorm.Model
	Slug        string `json:"slug" gorm:"uniqueIndex"`
	Description string `json:"description"`
}

var (
	// ErrInvalidSlug is returned when a caller-supplied slug is empty or
	// contains characters outside the safe set.
	ErrInvalidSlug = errors.New("slug must be 6-64 chars of [a-zA-Z0-9_-]")
	// ErrSlugExists is returned when creating a sink whose slug is taken.
	ErrSlugExists = errors.New("a sink with that slug already exists")

	// Minimum 6 chars: a short custom slug (e.g. "api", "get") would match by
	// substring inside unrelated targets/headers and pull in noise.
	slugPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{6,64}$`)
)

// GenerateSlug returns a short, random slug for embedding in payloads. It uses
// lowercase base32 (not model.randomToken's base64url) so the slug is a valid
// DNS label — no '_' or uppercase — since slugs are often used as DNS subdomains.
func GenerateSlug() (string, error) {
	b := make([]byte, 6) // ~10 base32 chars
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

// ValidSlug reports whether s is an acceptable caller-supplied slug.
func ValidSlug(s string) bool { return slugPattern.MatchString(s) }

// CreateSink stores a new sink. If slug is empty a random one is generated.
func CreateSink(slug, description string) (*Sink, error) {
	if slug == "" {
		g, err := GenerateSlug()
		if err != nil {
			return nil, err
		}
		slug = g
	}
	if !ValidSlug(slug) {
		return nil, ErrInvalidSlug
	}
	s := &Sink{Slug: slug, Description: description}
	if err := DB().Create(s).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrSlugExists
		}
		return nil, err
	}
	return s, nil
}

// ListSinks returns all sinks, newest first.
func ListSinks() []Sink {
	var out []Sink
	DB().Order("created_at desc").Find(&out)
	return out
}

// SinkBySlug fetches a single sink by its slug.
func SinkBySlug(slug string) (*Sink, error) {
	var s Sink
	if err := DB().Where("slug = ?", slug).First(&s).Error; err != nil {
		return nil, err
	}
	return &s, nil
}

// UpdateSinkDescription sets a sink's description (the slug is immutable) and
// returns the updated record.
func UpdateSinkDescription(slug, description string) (*Sink, error) {
	s, err := SinkBySlug(slug)
	if err != nil {
		return nil, err
	}
	if err := DB().Model(s).Update("description", description).Error; err != nil {
		return nil, err
	}
	return s, nil
}

// DeleteSink removes a sink by slug. It hard-deletes (Unscoped) so the slug can
// be reused; a GORM soft-delete would leave the row occupying the unique index
// and make the slug permanently un-recreatable. Its interactions are left
// untouched (a separate table).
func DeleteSink(slug string) error {
	return DB().Unscoped().Where("slug = ?", slug).Delete(&Sink{}).Error
}

// sinkMatch scopes a query to interactions attributed to slug: the slug appears
// in the request target (HTTP path, DNS qname) or the raw request headers dump
// (HTTP request line + Host, so path/query/subdomain all correlate). LIKE
// wildcards in the slug are escaped so the match is literal — matching the SSE
// stream's strings.Contains — since ValidSlug permits '_' (a LIKE wildcard).
func sinkMatch(q *gorm.DB, slug string) *gorm.DB {
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(slug)
	like := "%" + esc + "%"
	return q.Where(`request_target LIKE ? ESCAPE '\' OR headers LIKE ? ESCAPE '\'`, like, like)
}

// SinkEvents returns the interactions attributed to the slug, newest first.
func SinkEvents(slug string, limit, offset int) []Interaction {
	var out []Interaction
	q := sinkMatch(DB().Model(&Interaction{}), slug).Order("created_at desc")
	if limit > 0 {
		q = q.Limit(limit)
	}
	if offset > 0 {
		q = q.Offset(offset)
	}
	q.Find(&out)
	return out
}

// SinkEventCount returns the number of interactions attributed to the slug.
func SinkEventCount(slug string) int64 {
	var n int64
	sinkMatch(DB().Model(&Interaction{}), slug).Count(&n)
	return n
}
