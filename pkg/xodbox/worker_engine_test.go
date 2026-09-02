package xodbox

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
)

// fakeWorker records its runs and can be held open, so a test can observe the
// engine while a run is in flight.
type fakeWorker struct {
	name     string
	schedule string

	mu    sync.Mutex
	runs  int
	err   error
	block chan struct{}
}

func (f *fakeWorker) Name() string     { return f.name }
func (f *fakeWorker) Schedule() string { return f.schedule }

func (f *fakeWorker) Run(ctx context.Context) error {
	f.mu.Lock()
	f.runs++
	block := f.block
	err := f.err
	f.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func (f *fakeWorker) runCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs
}

// waitFor polls cond until it holds or the deadline passes; manual runs are
// asynchronous by design.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestTriggerRunsWorkerOutOfSchedule(t *testing.T) {
	// A yearly schedule guarantees the run below came from the trigger.
	w := &fakeWorker{name: "purge", schedule: "@yearly"}
	we := newWorkerEngine([]types.Worker{w})
	we.start()
	defer we.stop()

	if err := we.trigger("purge"); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	waitFor(t, "the manual run to complete", func() bool { return w.runCount() == 1 })

	st := we.statuses()
	if len(st) != 1 {
		t.Fatalf("statuses() returned %d entries, want 1", len(st))
	}
	if st[0].Running {
		t.Error("worker still reported as running after the run finished")
	}
	if st[0].LastRun == nil {
		t.Error("LastRun not recorded after a manual run")
	}
	if st[0].LastError != "" {
		t.Errorf("LastError = %q, want empty", st[0].LastError)
	}
	if st[0].NextRun == nil {
		t.Error("NextRun should be set for a scheduled worker")
	}
}

func TestTriggerUnknownWorker(t *testing.T) {
	we := newWorkerEngine([]types.Worker{&fakeWorker{name: "purge", schedule: "@yearly"}})
	we.start()
	defer we.stop()

	if err := we.trigger("nope"); !errors.Is(err, types.ErrUnknownWorker) {
		t.Errorf("trigger(unknown) = %v, want ErrUnknownWorker", err)
	}
}

// A worker must never overlap with itself: a second trigger while one run is in
// flight is refused rather than queued.
func TestTriggerRefusesConcurrentRun(t *testing.T) {
	block := make(chan struct{})
	w := &fakeWorker{name: "purge", schedule: "@yearly", block: block}
	we := newWorkerEngine([]types.Worker{w})
	we.start()
	defer we.stop()

	if err := we.trigger("purge"); err != nil {
		t.Fatalf("first trigger: %v", err)
	}
	waitFor(t, "the first run to start", func() bool { return w.runCount() == 1 })

	if err := we.trigger("purge"); !errors.Is(err, types.ErrWorkerBusy) {
		t.Errorf("second trigger = %v, want ErrWorkerBusy", err)
	}

	// While blocked, status must say so.
	st := we.statuses()
	if !st[0].Running {
		t.Error("Running = false during an in-flight run")
	}

	close(block)
	waitFor(t, "the run to finish", func() bool { return !we.statuses()[0].Running })

	if w.runCount() != 1 {
		t.Errorf("worker ran %d times, want 1 (the refused trigger must not run)", w.runCount())
	}
}

func TestStatusRecordsRunError(t *testing.T) {
	w := &fakeWorker{name: "purge", schedule: "@yearly", err: errors.New("vacuum failed")}
	we := newWorkerEngine([]types.Worker{w})
	we.start()
	defer we.stop()

	if err := we.trigger("purge"); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	waitFor(t, "the failing run to complete", func() bool {
		return we.statuses()[0].LastError != ""
	})

	if got := we.statuses()[0].LastError; got != "vacuum failed" {
		t.Errorf("LastError = %q, want %q", got, "vacuum failed")
	}
}

// Triggering before start() must still work: the engine falls back to a
// background context rather than panicking on a nil one.
func TestTriggerBeforeStart(t *testing.T) {
	w := &fakeWorker{name: "purge", schedule: "@yearly"}
	we := newWorkerEngine([]types.Worker{w})

	if err := we.trigger("purge"); err != nil {
		t.Fatalf("trigger before start: %v", err)
	}
	waitFor(t, "the run to complete", func() bool { return w.runCount() == 1 })

	// No cron entry yet, so there is no next fire time to report.
	if st := we.statuses(); st[0].NextRun != nil {
		t.Error("NextRun should be nil before the scheduler is started")
	}
}

func TestStatusesEmptyEngine(t *testing.T) {
	we := newWorkerEngine(nil)
	if got := we.statuses(); len(got) != 0 {
		t.Errorf("statuses() = %v, want empty", got)
	}
}

// Shutdown cancels the context handed to in-flight workers so they can bail out.
func TestStopCancelsRunningWorker(t *testing.T) {
	block := make(chan struct{})
	defer close(block)

	w := &fakeWorker{name: "purge", schedule: "@yearly", block: block}
	we := newWorkerEngine([]types.Worker{w})
	we.start()

	if err := we.trigger("purge"); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	waitFor(t, "the run to start", func() bool { return w.runCount() == 1 })

	we.stop()

	waitFor(t, "the cancelled run to record its outcome", func() bool {
		return we.statuses()[0].LastError != ""
	})
	if got := we.statuses()[0].LastError; got != context.Canceled.Error() {
		t.Errorf("LastError = %q, want %q", got, context.Canceled)
	}
}

// --- App-level wiring ---

func TestAppWorkerStatusAndTrigger(t *testing.T) {
	w := &fakeWorker{name: "purge", schedule: "@yearly"}
	app := NewApp(&Config{
		TemplateData: map[string]string{},
		Workers:      []types.Worker{w},
	})

	if got := app.WorkerStatus(); len(got) != 1 || got[0].Name != "purge" {
		t.Fatalf("WorkerStatus() = %v, want one entry named purge", got)
	}

	if err := app.TriggerWorker("purge"); err != nil {
		t.Fatalf("TriggerWorker: %v", err)
	}
	waitFor(t, "the triggered run", func() bool { return w.runCount() == 1 })

	if err := app.TriggerWorker("nope"); !errors.Is(err, types.ErrUnknownWorker) {
		t.Errorf("TriggerWorker(unknown) = %v, want ErrUnknownWorker", err)
	}
}

// With no workers configured there is no engine, so a trigger is an unknown
// worker rather than a nil dereference.
func TestAppWithNoWorkers(t *testing.T) {
	app := NewApp(&Config{TemplateData: map[string]string{}})

	if got := app.WorkerStatus(); len(got) != 0 {
		t.Errorf("WorkerStatus() = %v, want empty", got)
	}
	if err := app.TriggerWorker("purge"); !errors.Is(err, types.ErrUnknownWorker) {
		t.Errorf("TriggerWorker = %v, want ErrUnknownWorker", err)
	}
}
