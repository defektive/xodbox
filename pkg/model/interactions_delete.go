package model

import (
	"gorm.io/gorm"
)

// idChunkSize caps how many IDs are bound into a single IN (...) clause.
// SQLite rejects statements with more than 32766 parameters ("too many SQL
// variables"), and a purge of a busy deployment easily matches more rows than
// that, so every ID list is processed in chunks well under the limit.
const idChunkSize = 500

// chunkIDs splits ids into consecutive slices of at most idChunkSize.
func chunkIDs(ids []uint) [][]uint {
	var chunks [][]uint
	for len(ids) > idChunkSize {
		chunks = append(chunks, ids[:idChunkSize])
		ids = ids[idChunkSize:]
	}
	if len(ids) > 0 {
		chunks = append(chunks, ids)
	}
	return chunks
}

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
		for _, chunk := range chunkIDs(ids) {
			var fileIDs []uint
			if err := tx.Model(&UploadedFile{}).
				Where("interaction_id IN ?", chunk).
				Pluck("id", &fileIDs).Error; err != nil {
				return err
			}

			if err := deleteFilesByID(tx, fileIDs); err != nil {
				return err
			}

			res := tx.Unscoped().Where("id IN ?", chunk).Delete(&Interaction{})
			if res.Error != nil {
				return res.Error
			}
			deleted += res.RowsAffected
		}
		return nil
	})

	return deleted, err
}

// deleteFilesByID hard-deletes uploaded files, first making sure any
// deduplicated BLOB they hold survives for the rows that still reference it.
//
// Chunks are preserved and deleted one at a time, so each chunk's survivor
// check sees the earlier chunks already gone. A blob may be promoted into a
// row from a later chunk; that chunk then promotes it again, so the bytes
// always end up on a row that actually survives.
func deleteFilesByID(tx *gorm.DB, fileIDs []uint) error {
	for _, chunk := range chunkIDs(fileIDs) {
		if err := preserveDedupedFileData(tx, chunk); err != nil {
			return err
		}
		if err := tx.Unscoped().Where("id IN ?", chunk).Delete(&UploadedFile{}).Error; err != nil {
			return err
		}
	}
	return nil
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
		// Every file belonging to a soft-deleted interaction goes too, along
		// with files soft-deleted on their own. The subquery keeps the
		// interaction IDs out of bound parameters entirely.
		var fileIDs []uint
		if err := tx.Unscoped().Model(&UploadedFile{}).
			Where("deleted_at IS NOT NULL").
			Or("interaction_id IN (SELECT id FROM interactions WHERE deleted_at IS NOT NULL)").
			Pluck("id", &fileIDs).Error; err != nil {
			return err
		}

		if err := deleteFilesByID(tx, fileIDs); err != nil {
			return err
		}
		files = int64(len(fileIDs))

		res := tx.Unscoped().Where("deleted_at IS NOT NULL").Delete(&Interaction{})
		if res.Error != nil {
			return res.Error
		}
		interactions = res.RowsAffected
		return nil
	})

	if err != nil {
		return 0, 0, err
	}
	return interactions, files, nil
}
