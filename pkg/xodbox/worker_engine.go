package xodbox

import (
	"context"
	"sync"
	"time"

	"github.com/defektive/xodbox/pkg/types"
	"github.com/robfig/cron/v3"
)

// workerRun tracks one Worker and the outcome of its most recent run, so the
// management API and CLI can report whether a job actually did anything —
// otherwise a periodic job that silently does nothing is indistinguishable from
// one that is not scheduled at all.
type workerRun struct {
	worker  types.Worker
	entryID cron.EntryID

	mu      sync.Mutex
	running bool
	lastRun time.Time
	lastDur time.Duration
	lastErr error
}

// tryStart claims the worker for a run. It returns false when a run — scheduled
// or manual — is already in flight; a worker must never overlap with itself.
func (r *workerRun) tryStart() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		return false
	}
	r.running = true
	return true
}

func (r *workerRun) finish(start time.Time, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = false
	r.lastRun = start
	r.lastDur = time.Since(start)
	r.lastErr = err
}

// runClaimed executes the worker. The caller must already hold the claim from
// tryStart.
func (r *workerRun) runClaimed(ctx context.Context) error {
	start := time.Now()
	err := r.worker.Run(ctx)
	r.finish(start, err)
	return err
}

// execute claims and runs in one step, reporting ErrWorkerBusy if it cannot.
func (r *workerRun) execute(ctx context.Context) error {
	if !r.tryStart() {
		return types.ErrWorkerBusy
	}
	return r.runClaimed(ctx)
}

func (r *workerRun) status(next time.Time) types.WorkerStatus {
	r.mu.Lock()
	defer r.mu.Unlock()

	st := types.WorkerStatus{
		Name:     r.worker.Name(),
		Schedule: r.worker.Schedule(),
		Running:  r.running,
	}
	if !r.lastRun.IsZero() {
		last := r.lastRun
		st.LastRun = &last
		st.LastDurationMS = r.lastDur.Milliseconds()
	}
	if r.lastErr != nil {
		st.LastError = r.lastErr.Error()
	}
	if !next.IsZero() {
		n := next
		st.NextRun = &n
	}
	return st
}

// workerEngine manages the lifecycle of all configured Workers using a
// robfig/cron scheduler. It is created by NewApp and driven by Run/Shutdown.
type workerEngine struct {
	runs   []*workerRun
	byName map[string]*workerRun
	cron   *cron.Cron
	cancel context.CancelFunc

	// ctx is the run context handed to every worker, cancelled on shutdown.
	// Nil until start() is called.
	ctxMu sync.Mutex
	ctx   context.Context
}

func newWorkerEngine(workers []types.Worker) *workerEngine {
	we := &workerEngine{
		byName: map[string]*workerRun{},
		// SkipIfStillRunning: if a tick fires while a prior run is still
		// executing, the new tick is silently dropped — prevents pileups for
		// slow workers.
		cron: cron.New(cron.WithChain(
			cron.SkipIfStillRunning(cron.DefaultLogger),
		)),
	}
	for _, w := range workers {
		r := &workerRun{worker: w}
		we.runs = append(we.runs, r)
		// Last registration wins on a duplicate name, matching the cron
		// registrations below.
		we.byName[w.Name()] = r
	}
	return we
}

func (we *workerEngine) runContext() context.Context {
	we.ctxMu.Lock()
	defer we.ctxMu.Unlock()
	if we.ctx == nil {
		return context.Background()
	}
	return we.ctx
}

func (we *workerEngine) start() {
	ctx, cancel := context.WithCancel(context.Background())
	we.cancel = cancel

	we.ctxMu.Lock()
	we.ctx = ctx
	we.ctxMu.Unlock()

	for _, r := range we.runs {
		r := r
		w := r.worker
		id, err := we.cron.AddFunc(w.Schedule(), func() {
			if err := r.execute(we.runContext()); err != nil {
				lg().Error("worker run error", "worker", w.Name(), "err", err)
			}
		})
		if err != nil {
			lg().Error("failed to register worker schedule",
				"worker", w.Name(), "schedule", w.Schedule(), "err", err)
			continue
		}
		r.entryID = id
		lg().Info("worker registered", "worker", w.Name(), "schedule", w.Schedule())
	}

	we.cron.Start()
	lg().Info("worker engine started", "count", len(we.runs))
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

// statuses reports every configured worker, including its next scheduled fire
// time when the scheduler is running.
func (we *workerEngine) statuses() []types.WorkerStatus {
	out := make([]types.WorkerStatus, 0, len(we.runs))
	for _, r := range we.runs {
		var next time.Time
		if r.entryID != 0 {
			next = we.cron.Entry(r.entryID).Next
		}
		out = append(out, r.status(next))
	}
	return out
}

// trigger starts an out-of-schedule run of the named worker in the background,
// returning once the run is accepted. Manual runs are deliberately not
// synchronous: a purge that vacuums a large database can take minutes, far
// longer than an HTTP request should wait. Callers poll statuses() for the
// outcome.
func (we *workerEngine) trigger(name string) error {
	r, ok := we.byName[name]
	if !ok {
		return types.ErrUnknownWorker
	}
	if !r.tryStart() {
		return types.ErrWorkerBusy
	}

	ctx := we.runContext()
	go func() {
		lg().Info("manual worker run started", "worker", name)
		if err := r.runClaimed(ctx); err != nil {
			lg().Error("manual worker run failed", "worker", name, "err", err)
			return
		}
		lg().Info("manual worker run complete", "worker", name)
	}()
	return nil
}
