package model

import (
	"errors"

	"gorm.io/gorm"
)

// UploadedFile holds a single file part extracted from a multipart/form-data
// HTTP request. Files are associated with the Interaction that received them
// and stored as raw BLOBs in SQLite. ContentHash (SHA-256 hex) is used for
// deduplication: when a file with the same hash already exists, Data is left
// nil and the download handler resolves the bytes via FindFileByHash.
type UploadedFile struct {
	gorm.Model
	InteractionID uint   `json:"interaction_id" gorm:"index"`
	FileName      string `json:"file_name"`
	ContentType   string `json:"content_type"`
	Size          int64  `json:"size"`
	ContentHash   string `json:"content_hash" gorm:"index"`
	Data          []byte `json:"-"`
}

// FilesForInteraction returns all uploaded files for the given interaction ID,
// without the raw Data blob (use UploadedFileByID to fetch with data).
func FilesForInteraction(interactionID uint) []UploadedFile {
	var out []UploadedFile
	DB().Select("id, created_at, updated_at, deleted_at, interaction_id, file_name, content_type, size, content_hash").
		Where("interaction_id = ?", interactionID).
		Order("id asc").
		Find(&out)
	return out
}

// FindFileByHash returns the first uploaded file with the given SHA-256 content
// hash that has a non-empty Data blob (the canonical copy). Returns nil when no
// match is found.
func FindFileByHash(hash string) (*UploadedFile, error) {
	if hash == "" {
		return nil, errors.New("empty hash")
	}
	var f UploadedFile
	// Use length(data) > 0 instead of data != '' because SQLite evaluates
	// X'' != '' as TRUE (BLOB vs TEXT affinity), letting empty-BLOB rows slip
	// through and be returned as the canonical copy.
	err := DB().Where("content_hash = ? AND data IS NOT NULL AND length(data) > 0", hash).First(&f).Error
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// UploadedFileByID fetches a single uploaded file including its raw Data.
func UploadedFileByID(id uint) (*UploadedFile, error) {
	var f UploadedFile
	if err := DB().First(&f, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return nil, err
	}
	return &f, nil
}

// SinkFiles returns uploaded files attributed to interactions matching the
// given sink slug, newest first (by file creation time). The returned files
// do not include raw Data; use UploadedFileByID for that.
func SinkFiles(slug string, limit, offset int) ([]UploadedFile, int64) {
	var ids []uint
	var interactions []Interaction
	sinkMatch(DB().Model(&Interaction{}).Select("id"), slug).Find(&interactions)
	for _, i := range interactions {
		ids = append(ids, i.ID)
	}
	if len(ids) == 0 {
		return nil, 0
	}

	base := DB().Model(&UploadedFile{}).
		Select("id, created_at, updated_at, deleted_at, interaction_id, file_name, content_type, size, content_hash").
		Where("interaction_id IN ?", ids)

	var total int64
	base.Count(&total)

	var out []UploadedFile
	q := base.Session(&gorm.Session{}).Order("created_at desc")
	if limit > 0 {
		q = q.Limit(limit)
	}
	if offset > 0 {
		q = q.Offset(offset)
	}
	q.Find(&out)
	return out, total
}
