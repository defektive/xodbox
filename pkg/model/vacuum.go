package model

import (
	"os"
)

// Vacuum rebuilds the database file, returning space freed by deleted rows to
// the filesystem.
//
// SQLite moves the pages freed by a DELETE onto an internal freelist and reuses
// them for later writes; it never shrinks the file on its own. After a purge
// that removes gigabytes of request bodies the file therefore stays at its
// previous high-water mark until a VACUUM rewrites it.
//
// VACUUM rewrites the entire database, so it needs temporary free disk space
// roughly equal to the current file size and holds a write lock for the
// duration. Run it from a scheduled job, not from a request path.
func Vacuum() error {
	return DB().Exec("VACUUM").Error
}

// DBFileSize returns the size in bytes of the SQLite file backing the current
// connection, for reporting how much a purge actually reclaimed. Returns an
// error if the path is unknown (no database opened yet) or unreadable.
func DBFileSize() (int64, error) {
	fi, err := os.Stat(DBFilePath())
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}
