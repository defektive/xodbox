package dns

import (
	"context"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
)

func TestStopBeforeStartIsNoOp(t *testing.T) {
	h := NewHandler(map[string]string{"listener": "127.0.0.1:0", "default_ip": "1.1.1.1"}).(*Handler)
	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("Stop before Start = %v, want nil", err)
	}
}

func TestStopUnblocksStart(t *testing.T) {
	addr := freeUDPPort(t)
	h := NewHandler(map[string]string{"listener": addr, "default_ip": "1.1.1.1"}).(*Handler)

	done := make(chan error, 1)
	go func() {
		done <- h.Start(nil, make(chan types.InteractionEvent, 16))
	}()

	// Give the server a moment to bind. dns.Server doesn't expose a
	// ready signal cleanly; 100ms is plenty for loopback UDP.
	time.Sleep(200 * time.Millisecond)

	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("Stop = %v, want nil", err)
	}

	select {
	case <-done:
		// any return (nil or err) within deadline counts as unblocked.
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return within 2s of Stop")
	}
}
