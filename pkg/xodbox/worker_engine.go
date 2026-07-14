package xodbox

import (
	"context"
	"time"

	"github.com/defektive/xodbox/pkg/types"
	"github.com/robfig/cron/v3"
)

// workerEngine manages the lifecycle of all configured Workers using a
// robfig/cron scheduler. It is created by NewApp and driven by Run/Shutdown.
type workerEngine struct {
	workers []types.Worker
	cron    *cron.Cron
	cancel  context.CancelFunc
}

func newWorkerEngine(workers []types.Worker) *workerEngine {
	return &workerEngine{
		workers: workers,
		// SkipIfStillRunning: if a tick fires while a prior run is still
		// executing, the new tick is silently dropped — prevents pileups for
		// slow workers.
		cron: cron.New(cron.WithChain(
			cron.SkipIfStillRunning(cron.DefaultLogger),
		)),
	}
}

func (we *workerEngine) start() {
	ctx, cancel := context.WithCancel(context.Background())
	we.cancel = cancel

	for _, w := range we.workers {
		w := w
		if _, err := we.cron.AddFunc(w.Schedule(), func() {
			if err := w.Run(ctx); err != nil {
				lg().Error("worker run error", "worker", w.Name(), "err", err)
			}
		}); err != nil {
			lg().Error("failed to register worker schedule",
				"worker", w.Name(), "schedule", w.Schedule(), "err", err)
		} else {
			lg().Info("worker registered", "worker", w.Name(), "schedule", w.Schedule())
		}
	}

	we.cron.Start()
	lg().Info("worker engine started", "count", len(we.workers))
}

func (we *workerEngine) stop() {
	if we.cancel != nil {
		we.cancel()
	}
	// cron.Stop() prevents new ticks and returns a context that is Done once
	// all currently-executing jobs return. Use the same bound as handler
	// shutdown so a stuck worker can't keep the process alive indefinitely.
	stopCtx := we.cron.Stop()
	select {
	case <-stopCtx.Done():
	case <-time.After(shutdownTimeout):
		lg().Warn("worker engine did not stop within deadline; continuing shutdown")
	}
	lg().Info("worker engine stopped")
}
