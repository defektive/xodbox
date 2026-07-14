package purge

import (
	"context"
	"strconv"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
)

type Worker struct {
	schedule   string
	maxAgeDays int
}

func NewWorker(cfg map[string]string) types.Worker {
	schedule := cfg["schedule"]
	if schedule == "" {
		schedule = "@daily"
	}
	days := 30
	if v := cfg["max_age_days"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			days = n
		}
	}
	return &Worker{schedule: schedule, maxAgeDays: days}
}

func (w *Worker) Name() string     { return "purge" }
func (w *Worker) Schedule() string { return w.schedule }

func (w *Worker) Run(ctx context.Context) error {
	n, err := model.PurgeInteractionsOlderThan(w.maxAgeDays)
	if err != nil {
		lg().Error("purge run failed", "err", err)
		return err
	}
	lg().Info("purge complete", "deleted", n, "max_age_days", w.maxAgeDays)
	return nil
}
