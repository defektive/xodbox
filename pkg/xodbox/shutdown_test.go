package xodbox

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
)

type stoppableHandler struct {
	started chan struct{}
	stopped int32
	wait    chan struct{}
}

func (s *stoppableHandler) Name() string { return "stoppable" }

func (s *stoppableHandler) Start(_ types.App, _ chan types.InteractionEvent) error {
	close(s.started)
	<-s.wait
	return nil
}

func (s *stoppableHandler) Stop(_ context.Context) error {
	// Idempotent: stub may be Stop'd more than once.
	if atomic.CompareAndSwapInt32(&s.stopped, 0, 1) {
		close(s.wait)
	}
	return nil
}

type erroringStop struct{ stoppableHandler }

func (e *erroringStop) Stop(ctx context.Context) error {
	_ = e.stoppableHandler.Stop(ctx)
	return errors.New("stop failed")
}

func TestAppShutdownInvokesAllHandlers(t *testing.T) {
	h1 := &stoppableHandler{started: make(chan struct{}), wait: make(chan struct{})}
	h2 := &stoppableHandler{started: make(chan struct{}), wait: make(chan struct{})}

	app := NewApp(&Config{
		Handlers: []types.Handler{h1, h2},
	})

	runDone := make(chan struct{})
	go func() {
		app.Run()
		close(runDone)
	}()

	// Wait for both handlers to have entered Start.
	<-h1.started
	<-h2.started

	app.Shutdown()

	if atomic.LoadInt32(&h1.stopped) != 1 {
		t.Error("h1.Stop was not called")
	}
	if atomic.LoadInt32(&h2.stopped) != 1 {
		t.Error("h2.Stop was not called")
	}

	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of Shutdown")
	}
}

func TestAppShutdownIdempotent(t *testing.T) {
	h := &stoppableHandler{started: make(chan struct{}), wait: make(chan struct{})}
	app := NewApp(&Config{Handlers: []types.Handler{h}})

	go app.Run()
	<-h.started

	// Two consecutive shutdowns must not panic on a double channel close.
	app.Shutdown()
	app.Shutdown()
}

func TestAppShutdownContinuesOnHandlerError(t *testing.T) {
	bad := &erroringStop{stoppableHandler{started: make(chan struct{}), wait: make(chan struct{})}}
	good := &stoppableHandler{started: make(chan struct{}), wait: make(chan struct{})}

	app := NewApp(&Config{Handlers: []types.Handler{bad, good}})
	go app.Run()
	<-bad.started
	<-good.started

	app.Shutdown()

	if atomic.LoadInt32(&good.stopped) != 1 {
		t.Error("a handler that errors should not block subsequent Stops")
	}
}
