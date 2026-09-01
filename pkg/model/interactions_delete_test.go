package model

import (
	"os"
	"testing"
	"time"
)

// rawCount counts rows straight from SQLite, bypassing GORM's soft-delete
// scope, so a test can tell "hidden from queries" apart from "actually gone".
func rawCount(t *testing.T, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := DB().Raw(query, args...).Scan(&n).Error; err != nil {
		t.Fatalf("raw count: %v", err)
	}
	return n
}

// seedAged creates an interaction and backdates it by the given number of days.
func seedAged(t *testing.T, ix Interaction, ageDays int) Interaction {
	t.Helper()
	if err := DB().Create(&ix).Error; err != nil {
		t.Fatalf("seed interaction: %v", err)
	}
	if ageDays > 0 {
		when := time.Now().AddDate(0, 0, -ageDays)
		if err := DB().Model(&Interaction{}).Where("id = ?", ix.ID).
			Update("created_at", when).Error; err != nil {
			t.Fatalf("backdate interaction: %v", err)
		}
	}
	return ix
}

func seedFile(t *testing.T, f UploadedFile) UploadedFile {
	t.Helper()
	if err := DB().Create(&f).Error; err != nil {
		t.Fatalf("seed file: %v", err)
	}
	return f
}

// TestPurgeOlderThanHardDeletes is the regression test for the original bug:
// the purge worker soft-deleted, so rows vanished from the UI while their
// (often very large) BLOBs stayed in the database file forever.
func TestPurgeOlderThanHardDeletes(t *testing.T) {
	resetDB(t)

	old := seedAged(t, Interaction{Handler: "httpx", RequestTarget: "/old", Data: []byte("old body")}, 90)
	recent := seedAged(t, Interaction{Handler: "httpx", RequestTarget: "/new", Data: []byte("new body")}, 1)
	seedFile(t, UploadedFile{InteractionID: old.ID, FileName: "old.bin", ContentHash: "hash-old", Data: []byte("old bytes")})
	seedFile(t, UploadedFile{InteractionID: recent.ID, FileName: "new.bin", ContentHash: "hash-new", Data: []byte("new bytes")})

	n, err := PurgeInteractionsOlderThan(30)
	if err != nil {
		t.Fatalf("PurgeInteractionsOlderThan: %v", err)
	}
	if n != 1 {
		t.Fatalf("deleted %d interactions, want 1", n)
	}

	if got := rawCount(t, "select count(*) from interactions where id = ?", old.ID); got != 0 {
		t.Errorf("purged interaction still present in the table (%d rows); it was only soft-deleted", got)
	}
	if got := rawCount(t, "select count(*) from uploaded_files where interaction_id = ?", old.ID); got != 0 {
		t.Errorf("purged interaction's file still present (%d rows); the BLOB was not reclaimed", got)
	}

	// The in-window interaction and its file must be untouched.
	if got := rawCount(t, "select count(*) from interactions where id = ?", recent.ID); got != 1 {
		t.Errorf("recent interaction rows = %d, want 1", got)
	}
	if got := rawCount(t, "select count(*) from uploaded_files where interaction_id = ?", recent.ID); got != 1 {
		t.Errorf("recent interaction's file rows = %d, want 1", got)
	}
}

func TestPurgeOlderThanRejectsNonPositiveDays(t *testing.T) {
	resetDB(t)
	for _, days := range []int{0, -1} {
		if _, err := PurgeInteractionsOlderThan(days); err == nil {
			t.Errorf("PurgeInteractionsOlderThan(%d) should error, got nil", days)
		}
	}
}

func TestPurgeOlderThanNoMatchesIsNoop(t *testing.T) {
	resetDB(t)
	seedAged(t, Interaction{Handler: "httpx", RequestTarget: "/fresh"}, 1)

	n, err := PurgeInteractionsOlderThan(30)
	if err != nil {
		t.Fatalf("PurgeInteractionsOlderThan: %v", err)
	}
	if n != 0 {
		t.Errorf("deleted %d, want 0", n)
	}
	if got := rawCount(t, "select count(*) from interactions"); got != 1 {
		t.Errorf("interaction rows = %d, want 1", got)
	}
}

// TestPurgeFilterHardDeletesWithFiles covers the CLI purge path, which
// previously soft-deleted the interaction and never touched its files at all.
func TestPurgeFilterHardDeletes(t *testing.T) {
	resetDB(t)

	doomed := seedAged(t, Interaction{Handler: "httpx", RemoteAddr: "198.51.100.5", RequestTarget: "/beacon"}, 0)
	keep := seedAged(t, Interaction{Handler: "httpx", RemoteAddr: "8.8.8.8", RequestTarget: "/beacon"}, 0)
	seedFile(t, UploadedFile{InteractionID: doomed.ID, FileName: "d.bin", ContentHash: "h-doomed", Data: []byte("x")})

	n, err := PurgeInteractions(InteractionPurgeFilter{Remotes: []string{"198.51.100.0/24"}})
	if err != nil {
		t.Fatalf("PurgeInteractions: %v", err)
	}
	if n != 1 {
		t.Fatalf("deleted %d, want 1", n)
	}

	if got := rawCount(t, "select count(*) from interactions where id = ?", doomed.ID); got != 0 {
		t.Errorf("purged row still in the table (%d)", got)
	}
	if got := rawCount(t, "select count(*) from uploaded_files where interaction_id = ?", doomed.ID); got != 0 {
		t.Errorf("purged row's file still in the table (%d)", got)
	}
	if got := rawCount(t, "select count(*) from interactions where id = ?", keep.ID); got != 1 {
		t.Errorf("non-matching row was deleted")
	}
}

func TestDeleteInteractionHardDeletes(t *testing.T) {
	resetDB(t)

	ix := seedAged(t, Interaction{Handler: "httpx", RequestTarget: "/one"}, 0)
	seedFile(t, UploadedFile{InteractionID: ix.ID, FileName: "a.bin", ContentHash: "h-a", Data: []byte("a")})

	if err := DeleteInteraction(ix.ID); err != nil {
		t.Fatalf("DeleteInteraction: %v", err)
	}
	if got := rawCount(t, "select count(*) from interactions where id = ?", ix.ID); got != 0 {
		t.Errorf("interaction rows = %d, want 0", got)
	}
	if got := rawCount(t, "select count(*) from uploaded_files where interaction_id = ?", ix.ID); got != 0 {
		t.Errorf("uploaded_files rows = %d, want 0", got)
	}
}

func TestDeleteFileHardDeletes(t *testing.T) {
	resetDB(t)

	ix := seedAged(t, Interaction{Handler: "httpx", RequestTarget: "/f"}, 0)
	f := seedFile(t, UploadedFile{InteractionID: ix.ID, FileName: "a.bin", ContentHash: "h-a", Data: []byte("a")})

	if err := DeleteFile(f.ID); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}
	if got := rawCount(t, "select count(*) from uploaded_files where id = ?", f.ID); got != 0 {
		t.Errorf("uploaded_files rows = %d, want 0", got)
	}
}

// TestPurgePreservesDedupedBlob guards the hazard hard deletes introduce:
// uploads are stored once per SHA-256, so removing whichever interaction
// happens to hold the canonical bytes must not orphan surviving duplicates.
func TestPurgePreservesDedupedBlob(t *testing.T) {
	resetDB(t)

	const hash = "shared-hash"
	payload := []byte("the shared bytes")

	// Old interaction holds the canonical copy; the recent one is a dedup
	// pointer with an empty Data, exactly as parseRawBody stores it.
	oldIx := seedAged(t, Interaction{Handler: "httpx", RequestTarget: "/old"}, 90)
	newIx := seedAged(t, Interaction{Handler: "httpx", RequestTarget: "/new"}, 1)
	seedFile(t, UploadedFile{InteractionID: oldIx.ID, FileName: "dup.bin", ContentHash: hash, Size: int64(len(payload)), Data: payload})
	survivor := seedFile(t, UploadedFile{InteractionID: newIx.ID, FileName: "dup.bin", ContentHash: hash, Size: int64(len(payload))})

	if _, err := PurgeInteractionsOlderThan(30); err != nil {
		t.Fatalf("PurgeInteractionsOlderThan: %v", err)
	}

	// The survivor must still resolve to real bytes, not an empty file.
	got, err := FindFileByHash(hash)
	if err != nil {
		t.Fatalf("FindFileByHash after purge: %v (the deduplicated blob was orphaned)", err)
	}
	if got.ID != survivor.ID {
		t.Errorf("canonical copy is file %d, want the surviving file %d", got.ID, survivor.ID)
	}
	if string(got.Data) != string(payload) {
		t.Errorf("survivor Data = %q, want %q", got.Data, payload)
	}
}

// When nothing survives that needs the bytes, they should just go away rather
// than being promoted somewhere.
func TestPurgeDropsBlobWithNoSurvivor(t *testing.T) {
	resetDB(t)

	const hash = "lonely-hash"
	ix := seedAged(t, Interaction{Handler: "httpx", RequestTarget: "/only"}, 90)
	seedFile(t, UploadedFile{InteractionID: ix.ID, FileName: "only.bin", ContentHash: hash, Data: []byte("bytes")})

	if _, err := PurgeInteractionsOlderThan(30); err != nil {
		t.Fatalf("PurgeInteractionsOlderThan: %v", err)
	}
	if got := rawCount(t, "select count(*) from uploaded_files where content_hash = ?", hash); got != 0 {
		t.Errorf("uploaded_files rows = %d, want 0", got)
	}
}

// TestPurgeSoftDeletedSweep covers the upgrade path: rows a previous build
// soft-deleted are invisible to every query but still occupy the file, so the
// worker sweeps them.
func TestPurgeSoftDeletedSweep(t *testing.T) {
	resetDB(t)

	stale := seedAged(t, Interaction{Handler: "httpx", RequestTarget: "/stale"}, 1)
	staleFile := seedFile(t, UploadedFile{InteractionID: stale.ID, FileName: "s.bin", ContentHash: "h-s", Data: []byte("s")})
	live := seedAged(t, Interaction{Handler: "httpx", RequestTarget: "/live"}, 1)
	liveFile := seedFile(t, UploadedFile{InteractionID: live.ID, FileName: "l.bin", ContentHash: "h-l", Data: []byte("l")})

	// Simulate what an older build left behind.
	now := time.Now()
	if err := DB().Model(&Interaction{}).Where("id = ?", stale.ID).Update("deleted_at", now).Error; err != nil {
		t.Fatalf("soft-delete interaction: %v", err)
	}
	if err := DB().Model(&UploadedFile{}).Where("id = ?", staleFile.ID).Update("deleted_at", now).Error; err != nil {
		t.Fatalf("soft-delete file: %v", err)
	}

	ixN, fileN, err := PurgeSoftDeleted()
	if err != nil {
		t.Fatalf("PurgeSoftDeleted: %v", err)
	}
	if ixN != 1 {
		t.Errorf("swept %d interactions, want 1", ixN)
	}
	if fileN != 1 {
		t.Errorf("swept %d files, want 1", fileN)
	}

	if got := rawCount(t, "select count(*) from interactions where id = ?", stale.ID); got != 0 {
		t.Errorf("soft-deleted interaction still present (%d rows)", got)
	}
	if got := rawCount(t, "select count(*) from uploaded_files where id = ?", staleFile.ID); got != 0 {
		t.Errorf("soft-deleted file still present (%d rows)", got)
	}
	// Live rows must survive the sweep.
	if got := rawCount(t, "select count(*) from interactions where id = ?", live.ID); got != 1 {
		t.Errorf("live interaction was swept")
	}
	if got := rawCount(t, "select count(*) from uploaded_files where id = ?", liveFile.ID); got != 1 {
		t.Errorf("live file was swept")
	}
}

func TestPurgeSoftDeletedNoopWhenClean(t *testing.T) {
	resetDB(t)
	seedAged(t, Interaction{Handler: "httpx", RequestTarget: "/clean"}, 1)

	ixN, fileN, err := PurgeSoftDeleted()
	if err != nil {
		t.Fatalf("PurgeSoftDeleted: %v", err)
	}
	if ixN != 0 || fileN != 0 {
		t.Errorf("swept (%d, %d), want (0, 0)", ixN, fileN)
	}
	if got := rawCount(t, "select count(*) from interactions"); got != 1 {
		t.Errorf("interaction rows = %d, want 1", got)
	}
}

// TestVacuumShrinksFile is the other half of the fix: a hard delete alone
// leaves the pages on SQLite's freelist and the file at its high-water mark.
func TestVacuumShrinksFile(t *testing.T) {
	resetDB(t)

	// ~8 MB of bodies, enough that the file growth is unambiguous.
	blob := make([]byte, 512*1024)
	for i := range blob {
		blob[i] = byte(i % 251)
	}
	for i := 0; i < 16; i++ {
		seedAged(t, Interaction{Handler: "httpx", RequestTarget: "/big", Data: blob}, 90)
	}

	grown, err := DBFileSize()
	if err != nil {
		t.Fatalf("DBFileSize: %v", err)
	}

	if _, err := PurgeInteractionsOlderThan(30); err != nil {
		t.Fatalf("PurgeInteractionsOlderThan: %v", err)
	}

	// Before VACUUM the freed pages are on the freelist; the file is unchanged.
	var freelist int64
	if err := DB().Raw("pragma freelist_count").Scan(&freelist).Error; err != nil {
		t.Fatalf("pragma freelist_count: %v", err)
	}
	if freelist == 0 {
		t.Error("expected freed pages on the freelist after a hard delete")
	}

	if err := Vacuum(); err != nil {
		t.Fatalf("Vacuum: %v", err)
	}

	shrunk, err := DBFileSize()
	if err != nil {
		t.Fatalf("DBFileSize after vacuum: %v", err)
	}
	if shrunk >= grown {
		t.Errorf("file did not shrink: %d bytes before vacuum, %d after", grown, shrunk)
	}
}

func TestDBFilePathTracksOpenDatabase(t *testing.T) {
	resetDB(t)
	p := DBFilePath()
	if p == "" {
		t.Fatal("DBFilePath() is empty after loading a database")
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("DBFilePath() = %q, which does not exist: %v", p, err)
	}
}
