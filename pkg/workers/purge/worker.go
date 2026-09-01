package purge

import (
	"context"
	"strconv"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
)

const (
	defaultSchedule   = "@daily"
	defaultMaxAgeDays = 30
)

type Worker struct {
	schedule   string
	maxAgeDays int
	vacuum     bool
}

func NewWorker(cfg map[string]string) types.Worker {
	schedule := cfg["schedule"]
	if schedule == "" {
		schedule = defaultSchedule
	}
	days := defaultMaxAgeDays
	if v := cfg["max_age_days"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			days = n
		}
	}
	// VACUUM defaults on: without it a purge frees pages onto SQLite's internal
	// freelist but the file never shrinks, which is the symptom most operators
	// are trying to fix by enabling this worker in the first place.
	vacuum := true
	if v := cfg["vacuum"]; v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			vacuum = b
		}
	}
	return &Worker{schedule: schedule, maxAgeDays: days, vacuum: vacuum}
}

func (w *Worker) Name() string     { return "purge" }
func (w *Worker) Schedule() string { return w.schedule }

func (w *Worker) Run(ctx context.Context) error {
	// Best-effort: a failed stat only costs us the reclaimed-bytes log field.
	sizeBefore, sizeErr := model.DBFileSize()

	n, err := model.PurgeInteractionsOlderThan(w.maxAgeDays)
	if err != nil {
		lg().Error("purge run failed", "err", err)
		return err
	}

	// Sweep anything an earlier build (or the UI delete action) soft-deleted;
	// those rows hold their BLOBs indefinitely and no query can ever see them.
	sweptRows, sweptFiles, err := model.PurgeSoftDeleted()
	if err != nil {
		lg().Error("purge of soft-deleted rows failed", "err", err)
		return err
	}

	// Files alone can account for the bulk of the freed space, so a sweep that
	// only removed uploads still earns a vacuum.
	deleted := n + sweptRows + sweptFiles
	lg().Info("purge complete",
		"deleted", n,
		"soft_deleted_swept", sweptRows,
		"files_removed", sweptFiles,
		"max_age_days", w.maxAgeDays)

	if !w.vacuum || deleted == 0 {
		return nil
	}

	// Skip the rewrite if shutdown already started — VACUUM on a large file can
	// take a while and holds a write lock throughout.
	if err := ctx.Err(); err != nil {
		lg().Info("skipping vacuum, shutting down")
		return nil
	}

	if err := model.Vacuum(); err != nil {
		lg().Error("vacuum failed", "err", err)
		return err
	}

	if sizeErr == nil {
		if sizeAfter, err := model.DBFileSize(); err == nil {
			lg().Info("vacuum complete",
				"bytes_before", sizeBefore,
				"bytes_after", sizeAfter,
				"bytes_reclaimed", sizeBefore-sizeAfter)
			return nil
		}
	}
	lg().Info("vacuum complete")
	return nil
}
