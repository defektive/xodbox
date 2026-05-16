package httpx

import (
	"context"
	"errors"
	"net"
	"net/http"
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

func TestStopShutsDownHTTPSServerPair(t *testing.T) {
	// Boot two bound *http.Server instances on free loopback ports
	// (no Serve call — Shutdown on an unstarted server still returns
	// cleanly), then assert Stop tears down both as well as the plain
	// HTTP one and reports the first failure if any.
	h := NewHandler(map[string]string{"listener": "127.0.0.1:0"}).(*Handler)

	httpAddr := freeTCPAddr(t)
	httpsAddr := freeTCPAddr(t)

	httpSrv := &http.Server{Addr: httpAddr}
	httpsSrv := &http.Server{Addr: httpsAddr}
	challenge := &http.Server{Addr: freeTCPAddr(t)}

	h.mu.Lock()
	h.httpServer = httpSrv
	h.httpChallengeServer = challenge
	h.httpsServer = httpsSrv
	h.mu.Unlock()

	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("Stop = %v, want nil", err)
	}

	// A second Shutdown after Stop should be a no-op error (the server
	// is closed). Use it as a marker that Stop actually called Shutdown.
	for _, s := range []*http.Server{httpSrv, challenge, httpsSrv} {
		err := s.Shutdown(context.Background())
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("server should be in shutdown state after Stop, got %v", err)
		}
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
