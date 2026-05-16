package xodbox

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/defektive/xodbox/pkg/types"
)

type seederHandler struct {
	stoppableHandler
	seeded int32
	err    error
}

func (s *seederHandler) Seed() error {
	atomic.AddInt32(&s.seeded, 1)
	return s.err
}

func TestNewAppCallsSeederOnImplementingHandlers(t *testing.T) {
	seeded := &seederHandler{
		stoppableHandler: stoppableHandler{
			started: make(chan struct{}),
			wait:    make(chan struct{}),
		},
	}
	plain := &stoppableHandler{
		started: make(chan struct{}),
		wait:    make(chan struct{}),
	}

	_ = NewApp(&Config{Handlers: []types.Handler{seeded, plain}})

	if got := atomic.LoadInt32(&seeded.seeded); got != 1 {
		t.Errorf("seeded.Seed call count = %d, want 1", got)
	}
}

func TestNewAppContinuesOnSeedError(t *testing.T) {
	bad := &seederHandler{
		stoppableHandler: stoppableHandler{
			started: make(chan struct{}),
			wait:    make(chan struct{}),
		},
		err: errors.New("seed boom"),
	}
	good := &seederHandler{
		stoppableHandler: stoppableHandler{
			started: make(chan struct{}),
			wait:    make(chan struct{}),
		},
	}

	_ = NewApp(&Config{Handlers: []types.Handler{bad, good}})

	if atomic.LoadInt32(&good.seeded) != 1 {
		t.Error("a Seeder that errors should not stop later seeders from running")
	}
}

func TestSeederContract(t *testing.T) {
	// Compile-time assertion that *seederHandler satisfies types.Seeder.
	var _ types.Seeder = (*seederHandler)(nil)
}

// Make sure stoppableHandler still has the right shape after the
// shutdown_test additions — the Seed method should not conflict.
func TestSeederStopShape(t *testing.T) {
	s := &seederHandler{
		stoppableHandler: stoppableHandler{
			started: make(chan struct{}),
			wait:    make(chan struct{}),
		},
	}
	// Stop() is inherited from stoppableHandler — must still work.
	if err := s.Stop(context.Background()); err != nil {
		t.Errorf("Stop returned %v, want nil", err)
	}
}
