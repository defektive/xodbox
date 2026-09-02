package model

import (
	"gorm.io/gorm"
)

// deleteInteractionsByID permanently removes the given interactions and every
// uploaded file attached to them.
//
// Deletes are Unscoped (hard) on purpose. Interaction and UploadedFile both
// embed gorm.Model, so an ordinary Delete only stamps deleted_at and leaves the
// row — including the raw request body and any file BLOB, which are routinely
// tens of megabytes — in the database file forever. Nothing in xodbox ever
// reads a soft-deleted interaction back (there is no restore or trash view), so
// the retained bytes were pure dead weight that defeated the whole point of a
// retention policy.
//
// Returns the number of interaction rows removed.
func deleteInteractionsByID(ids []uint) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}

	var deleted int64
	err := DB().Transaction(func(tx *gorm.DB) error {
		var fileIDs []uint
		if err := tx.Model(&UploadedFile{}).
			Where("interaction_id IN ?", ids).
			Pluck("id", &fileIDs).Error; err != nil {
			return err
		}

		if err := deleteFilesByID(tx, fileIDs); err != nil {
			return err
		}

		res := tx.Unscoped().Where("id IN ?", ids).Delete(&Interaction{})
		if res.Error != nil {
			return res.Error
		}
		deleted = res.RowsAffected
		return nil
	})

	return deleted, err
}

// deleteFilesByID hard-deletes uploaded files, first making sure any
// deduplicated BLOB they hold survives for the rows that still reference it.
func deleteFilesByID(tx *gorm.DB, fileIDs []uint) error {
	if len(fileIDs) == 0 {
		return nil
	}
	if err := preserveDedupedFileData(tx, fileIDs); err != nil {
		return err
	}
	return tx.Unscoped().Where("id IN ?", fileIDs).Delete(&UploadedFile{}).Error
}

// preserveDedupedFileData keeps deduplicated uploads downloadable across a
// purge.
//
// Uploads are stored once per SHA-256: the first copy holds the bytes and every
// later duplicate stores an empty Data, resolving the blob through
// FindFileByHash at download time. Hard-deleting whichever interaction happens
// to hold the canonical copy would therefore orphan every surviving duplicate,
// turning their downloads into empty files. Before the delete, promote the
// bytes into one of the survivors.
//
// The copy is done with an UPDATE ... SELECT so the blob never round-trips
// through Go memory.
func preserveDedupedFileData(tx *gorm.DB, doomed []uint) error {
	if len(doomed) == 0 {
		return nil
	}

	// id + hash only — never SELECT the blob itself here.
	var canonical []UploadedFile
	if err := tx.Unscoped().Model(&UploadedFile{}).
		Select("id, content_hash").
		Where("id IN ? AND content_hash != '' AND data IS NOT NULL AND length(data) > 0", doomed).
		Find(&canonical).Error; err != nil {
		return err
	}

	for _, f := range canonical {
		// Does a row that survives this delete already hold the bytes?
		var stillHeld int64
		if err := tx.Model(&UploadedFile{}).
			Where("content_hash = ? AND id NOT IN ? AND data IS NOT NULL AND length(data) > 0", f.ContentHash, doomed).
			Count(&stillHeld).Error; err != nil {
			return err
		}
		if stillHeld > 0 {
			continue
		}

		// Pick the oldest surviving duplicate to inherit the blob.
		var heirs []uint
		if err := tx.Model(&UploadedFile{}).
			Where("content_hash = ? AND id NOT IN ?", f.ContentHash, doomed).
			Order("id asc").Limit(1).
			Pluck("id", &heirs).Error; err != nil {
			return err
		}
		if len(heirs) == 0 {
			// Nothing survives that needs these bytes; let them go.
			continue
		}

		if err := tx.Exec(
			"UPDATE uploaded_files SET data = (SELECT data FROM uploaded_files WHERE id = ?) WHERE id = ?",
			f.ID, heirs[0]).Error; err != nil {
			return err
		}
	}

	return nil
}

// PurgeSoftDeleted permanently removes interactions and uploaded files that
// were previously soft-deleted — by the UI/API delete actions or by a build of
// xodbox that soft-deleted on purge. Those rows are invisible to every query in
// the application yet still occupy the database file, so without this sweep an
// existing deployment can never reclaim what it already "deleted".
//
// Returns the number of interaction rows and file rows removed.
func PurgeSoftDeleted() (interactions int64, files int64, err error) {
	err = DB().Transaction(func(tx *gorm.DB) error {
		var ids []uint
		if err := tx.Unscoped().Model(&Interaction{}).
			Where("deleted_at IS NOT NULL").
			Pluck("id", &ids).Error; err != nil {
			return err
		}

		// Every file belonging to a soft-deleted interaction goes too, along
		// with files soft-deleted on their own.
		var fileIDs []uint
		q := tx.Unscoped().Model(&UploadedFile{}).Where("deleted_at IS NOT NULL")
		if len(ids) > 0 {
			q = q.Or("interaction_id IN ?", ids)
		}
		if err := q.Pluck("id", &fileIDs).Error; err != nil {
			return err
		}

		if err := deleteFilesByID(tx, fileIDs); err != nil {
			return err
		}
		files = int64(len(fileIDs))

		if len(ids) > 0 {
			res := tx.Unscoped().Where("id IN ?", ids).Delete(&Interaction{})
			if res.Error != nil {
				return res.Error
			}
			interactions = res.RowsAffected
		}
		return nil
	})

	if err != nil {
		return 0, 0, err
	}
	return interactions, files, nil
}
