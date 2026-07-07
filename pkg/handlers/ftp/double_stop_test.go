//go:build !race
// +build !race

package ftp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
)

// Regression: Handler.Stop nils h.server, so calling Stop twice after a Start
// must be idempotent and return nil both times.
//
// Tagged !race like stop_test.go: ftpserverlib's Start/Stop interaction trips
// the race detector internally (unrelated to the behaviour under test here).
func TestDoubleStopIsIdempotent(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)

	done := make(chan error, 1)
	go func() {
		done <- h.Start(nil, make(chan types.InteractionEvent, 16))
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
		t.Errorf("first Stop = %v, want nil", err)
	}
	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("second Stop = %v, want nil", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return within 2s of Stop")
	}
}
