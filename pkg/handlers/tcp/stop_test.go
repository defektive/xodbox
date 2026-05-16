package tcp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
)

func TestStopBeforeStartIsNoOp(t *testing.T) {
	h := NewHandler(map[string]string{"listener": "127.0.0.1:0"}).(*Handler)
	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("Stop before Start = %v, want nil", err)
	}
}

func TestStopUnblocksStart(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)

	done := make(chan error, 1)
	go func() {
		done <- h.Start(nil, make(chan types.InteractionEvent, 16))
	}()

	// Wait until the listener is up.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("Stop = %v, want nil", err)
	}

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("Start returned %v, want nil or ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return within 2s of Stop")
	}
}
