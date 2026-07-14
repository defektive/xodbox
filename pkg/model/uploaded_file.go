package model

import (
	"errors"

	"gorm.io/gorm"
)

// UploadedFile holds a single file part extracted from a multipart/form-data
// HTTP request. Files are associated with the Interaction that received them
// and stored as raw BLOBs in SQLite.
type UploadedFile struct {
	gorm.Model
	InteractionID uint   `json:"interaction_id" gorm:"index"`
	FileName      string `json:"file_name"`
	ContentType   string `json:"content_type"`
	Size          int64  `json:"size"`
	Data          []byte `json:"-"`
}

// FilesForInteraction returns all uploaded files for the given interaction ID,
// without the raw Data blob (use UploadedFileByID to fetch with data).
func FilesForInteraction(interactionID uint) []UploadedFile {
	var out []UploadedFile
	DB().Select("id, created_at, updated_at, deleted_at, interaction_id, file_name, content_type, size").
		Where("interaction_id = ?", interactionID).
		Order("id asc").
		Find(&out)
	return out
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
		Select("id, created_at, updated_at, deleted_at, interaction_id, file_name, content_type, size").
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
