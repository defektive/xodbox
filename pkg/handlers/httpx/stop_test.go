package httpx

import (
	"context"
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
	addr := freeTCPAddr(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)

	done := make(chan error, 1)
	go func() {
		done <- h.Start(&stubApp{data: map[string]string{}}, make(chan types.InteractionEvent, 16))
	}()

	// Wait for the listener to bind.
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
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return within 2s of Stop")
	}
}

func TestStopCancelsPayloadWatcher(t *testing.T) {
	dir := t.TempDir()
	h := NewHandler(map[string]string{
		"listener":    "127.0.0.1:0",
		"payload_dir": dir,
	}).(*Handler)

	// We can't directly observe the watcher goroutine, but we can
	// verify Stop returns nil and watchCancel is cleared, which means
	// the goroutine has been signalled to exit via ctx.Done().
	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("Stop = %v, want nil", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.watchCancel != nil {
		t.Error("watchCancel should be cleared after Stop")
	}
}
