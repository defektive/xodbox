package purge

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/model"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "purge-worker-test-*")
	if err != nil {
		panic(err)
	}
	model.LoadDBWithOptions(model.DBOptions{Path: filepath.Join(dir, "test.db")})
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func TestNewWorkerDefaults(t *testing.T) {
	w := NewWorker(map[string]string{}).(*Worker)
	if w.Name() != "purge" {
		t.Errorf("Name() = %q, want %q", w.Name(), "purge")
	}
	if w.Schedule() != defaultSchedule {
		t.Errorf("Schedule() = %q, want %q", w.Schedule(), defaultSchedule)
	}
	if w.maxAgeDays != defaultMaxAgeDays {
		t.Errorf("maxAgeDays = %d, want %d", w.maxAgeDays, defaultMaxAgeDays)
	}
	if !w.vacuum {
		t.Error("vacuum should default to true")
	}
}

func TestNewWorkerReadsConfig(t *testing.T) {
	w := NewWorker(map[string]string{
		"schedule":     "@every 6h",
		"max_age_days": "7",
		"vacuum":       "false",
	}).(*Worker)

	if w.Schedule() != "@every 6h" {
		t.Errorf("Schedule() = %q, want %q", w.Schedule(), "@every 6h")
	}
	if w.maxAgeDays != 7 {
		t.Errorf("maxAgeDays = %d, want 7", w.maxAgeDays)
	}
	if w.vacuum {
		t.Error("vacuum should be false when configured off")
	}
}

// Unparseable or non-positive values fall back to the defaults rather than
// disabling the worker or purging everything.
func TestNewWorkerIgnoresBadValues(t *testing.T) {
	cases := []map[string]string{
		{"max_age_days": "0"},
		{"max_age_days": "-5"},
		{"max_age_days": "banana"},
	}
	for _, cfg := range cases {
		w := NewWorker(cfg).(*Worker)
		if w.maxAgeDays != defaultMaxAgeDays {
			t.Errorf("cfg %v: maxAgeDays = %d, want %d", cfg, w.maxAgeDays, defaultMaxAgeDays)
		}
	}

	w := NewWorker(map[string]string{"vacuum": "not-a-bool"}).(*Worker)
	if !w.vacuum {
		t.Error("unparseable vacuum value should leave the default (true) in place")
	}
}

func TestNewWorkerVacuumAcceptedForms(t *testing.T) {
	for _, v := range []string{"false", "0", "f", "FALSE"} {
		if NewWorker(map[string]string{"vacuum": v}).(*Worker).vacuum {
			t.Errorf("vacuum=%q should disable vacuum", v)
		}
	}
	for _, v := range []string{"true", "1", "t", "TRUE"} {
		if !NewWorker(map[string]string{"vacuum": v}).(*Worker).vacuum {
			t.Errorf("vacuum=%q should enable vacuum", v)
		}
	}
}

func seedAged(t *testing.T, target string, ageDays int) model.Interaction {
	t.Helper()
	ix := model.Interaction{Handler: "httpx", RequestTarget: target, Data: []byte("body")}
	if err := model.DB().Create(&ix).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if ageDays > 0 {
		when := time.Now().AddDate(0, 0, -ageDays)
		if err := model.DB().Model(&model.Interaction{}).Where("id = ?", ix.ID).
			Update("created_at", when).Error; err != nil {
			t.Fatalf("backdate: %v", err)
		}
	}
	return ix
}

// seedAgedBlob writes n backdated interactions carrying a 256 KB body each, so
// that purging them frees whole SQLite pages and the freelist assertions below
// are meaningful.
func seedAgedBlob(t *testing.T, target string, n int) {
	t.Helper()
	blob := make([]byte, 256*1024)
	for i := 0; i < n; i++ {
		ix := model.Interaction{Handler: "httpx", RequestTarget: target, Data: blob}
		if err := model.DB().Create(&ix).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := model.DB().Model(&model.Interaction{}).Where("id = ?", ix.ID).
			Update("created_at", time.Now().AddDate(0, 0, -90)).Error; err != nil {
			t.Fatalf("backdate: %v", err)
		}
	}
}

func rawCount(t *testing.T, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := model.DB().Raw(query, args...).Scan(&n).Error; err != nil {
		t.Fatalf("raw count: %v", err)
	}
	return n
}

// End-to-end: a Run must actually remove the rows from the file, not just hide
// them behind deleted_at.
func TestRunHardDeletesAndVacuums(t *testing.T) {
	old := seedAged(t, "/worker-old", 90)
	recent := seedAged(t, "/worker-recent", 1)

	w := NewWorker(map[string]string{"max_age_days": "30"}).(*Worker)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := rawCount(t, "select count(*) from interactions where id = ?", old.ID); got != 0 {
		t.Errorf("aged interaction still in the table (%d rows)", got)
	}
	if got := rawCount(t, "select count(*) from interactions where id = ?", recent.ID); got != 1 {
		t.Errorf("in-window interaction was deleted")
	}

	// A vacuum leaves no free pages behind.
	var freelist int64
	if err := model.DB().Raw("pragma freelist_count").Scan(&freelist).Error; err != nil {
		t.Fatalf("pragma freelist_count: %v", err)
	}
	if freelist != 0 {
		t.Errorf("freelist_count = %d after a vacuuming run, want 0", freelist)
	}
}

func TestRunWithNothingToPurgeSucceeds(t *testing.T) {
	seedAged(t, "/worker-fresh", 1)
	w := NewWorker(map[string]string{"max_age_days": "30"}).(*Worker)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run with no matches: %v", err)
	}
}

// A cancelled context (shutdown in progress) must skip the VACUUM rewrite
// rather than holding a write lock on the way out.
func TestRunSkipsVacuumWhenContextCancelled(t *testing.T) {
	// Compact first, then seed enough data that the delete is guaranteed to
	// free whole pages — a handful of small rows may fit in already-used pages.
	if err := model.Vacuum(); err != nil {
		t.Fatalf("Vacuum: %v", err)
	}
	seedAgedBlob(t, "/worker-cancel", 8)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	w := NewWorker(map[string]string{"max_age_days": "30"}).(*Worker)
	if err := w.Run(ctx); err != nil {
		t.Fatalf("Run with cancelled context: %v", err)
	}

	// The delete still happened; only the rewrite was skipped, so the freed
	// pages are still on the freelist.
	var freelist int64
	if err := model.DB().Raw("pragma freelist_count").Scan(&freelist).Error; err != nil {
		t.Fatalf("pragma freelist_count: %v", err)
	}
	if freelist == 0 {
		t.Error("expected pages on the freelist; the vacuum should have been skipped")
	}
}

func TestRunVacuumDisabledLeavesFreelist(t *testing.T) {
	// Start from a compact file so the freelist below is unambiguous.
	if err := model.Vacuum(); err != nil {
		t.Fatalf("Vacuum: %v", err)
	}
	seedAgedBlob(t, "/worker-novac", 8)

	w := NewWorker(map[string]string{"max_age_days": "30", "vacuum": "false"}).(*Worker)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var freelist int64
	if err := model.DB().Raw("pragma freelist_count").Scan(&freelist).Error; err != nil {
		t.Fatalf("pragma freelist_count: %v", err)
	}
	if freelist == 0 {
		t.Error("vacuum was disabled, so the freed pages should still be on the freelist")
	}
}
