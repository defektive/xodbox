package xodbox

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
)

// closingHandler models a real listener: Start blocks until Stop, then
// reports why it came back. httpx returns http.ErrServerClosed here; the
// socket-based handlers return a "use of closed network connection" error.
// Either way the handler did not fail — it was stopped.
type closingHandler struct {
	started  chan struct{}
	returned chan struct{}
	wait     chan struct{}
	once     sync.Once
}

func newClosingHandler() *closingHandler {
	return &closingHandler{
		started:  make(chan struct{}),
		returned: make(chan struct{}),
		wait:     make(chan struct{}),
	}
}

func (c *closingHandler) Name() string { return "closing" }

func (c *closingHandler) Start(_ types.App, _ chan types.InteractionEvent) error {
	close(c.started)
	<-c.wait
	close(c.returned)
	return http.ErrServerClosed
}

func (c *closingHandler) Stop(_ context.Context) error {
	c.once.Do(func() { close(c.wait) })
	return nil
}

// failingHandler never comes up at all.
type failingHandler struct{ err error }

func (f *failingHandler) Name() string { return "failing" }
func (f *failingHandler) Start(_ types.App, _ chan types.InteractionEvent) error {
	return f.err
}
func (f *failingHandler) Stop(_ context.Context) error { return nil }

// captureExit swaps the package's exit hook for the duration of the test.
// The returned value holds the code passed to it, or -1 if it was never
// called.
func captureExit(t *testing.T) *atomic.Int32 {
	t.Helper()
	var code atomic.Int32
	code.Store(-1)
	old := exitFn
	exitFn = func(c int) { code.Store(int32(c)) }
	t.Cleanup(func() { exitFn = old })
	return &code
}

// becameTrue reports whether cond held at any point within d. Unlike
// waitFor it returns rather than failing, since these tests assert that
// something never happens.
func becameTrue(cond func() bool, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

// A config reload stops every handler and starts a fresh set. The stopped
// handlers' Start calls then return, and treating that as a startup failure
// used to take the whole process down (os.Exit(1)) mid-reload — so saving a
// config change from the admin UI killed the server.
func TestReloadSurvivesHandlersReturningAfterStop(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "xodbox.yaml")
	if err := os.WriteFile(cfgPath, []byte("handlers: []\nnotifiers: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldPath := ConfigFilePath
	ConfigFilePath = cfgPath
	t.Cleanup(func() { ConfigFilePath = oldPath })

	code := captureExit(t)

	h := newClosingHandler()
	app := NewApp(&Config{Handlers: []types.Handler{h}})
	go app.Run()
	<-h.started

	if err := app.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	<-h.returned

	if becameTrue(func() bool { return code.Load() != -1 }, 100*time.Millisecond) {
		t.Fatalf("reload exited the process with code %d; a stopped handler is not a startup failure", code.Load())
	}

	app.Shutdown()
}

// Same story on the way out: Shutdown stops the handlers, and their returns
// must not be mistaken for crashes.
func TestShutdownSurvivesHandlersReturningAfterStop(t *testing.T) {
	code := captureExit(t)

	h := newClosingHandler()
	app := NewApp(&Config{Handlers: []types.Handler{h}})
	go app.Run()
	<-h.started

	app.Shutdown()
	<-h.returned

	if becameTrue(func() bool { return code.Load() != -1 }, 100*time.Millisecond) {
		t.Fatalf("shutdown exited the process with code %d", code.Load())
	}
}

// A handler that genuinely cannot bind is still fatal at boot: a listening
// post that is not listening has nothing to offer.
func TestRunExitsWhenHandlerFailsToStart(t *testing.T) {
	code := captureExit(t)

	app := NewApp(&Config{Handlers: []types.Handler{
		&failingHandler{err: errors.New("listen tcp :9080: address already in use")},
	}})
	go app.Run()

	waitFor(t, "the failed handler to exit the process", func() bool { return code.Load() != -1 })
	if got := code.Load(); got != 1 {
		t.Errorf("exit code = %d, want 1", got)
	}

	app.Shutdown()
}

// After a reload, a handler that cannot bind is reported but not fatal: the
// old handlers are already stopped, so exiting would turn a bad config edit
// into an outage the operator cannot fix from the UI.
func TestReloadDoesNotExitWhenNewHandlerFailsToStart(t *testing.T) {
	code := captureExit(t)

	app := NewApp(&Config{})
	app.startHandlers([]types.Handler{
		&failingHandler{err: errors.New("listen tcp :9080: address already in use")},
	}, false)

	if becameTrue(func() bool { return code.Load() != -1 }, 200*time.Millisecond) {
		t.Fatalf("a failed post-reload start exited the process with code %d", code.Load())
	}
}
