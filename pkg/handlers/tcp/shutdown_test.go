package tcp

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
)

// dialWhenUp dials addr, retrying until the listener is accepting or the
// deadline expires. It mirrors the retry loop used elsewhere in this
// package's integration tests.
func dialWhenUp(t *testing.T, addr string) net.Conn {
	t.Helper()
	var conn net.Conn
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			return conn
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("dial handler: %v", err)
	return nil
}

// TestStopIsIdempotent calls Stop twice after a Start and asserts both
// return nil. Before the stopping guard, the second Close on the listener
// returned net.ErrClosed.
func TestStopIsIdempotent(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)

	done := make(chan error, 1)
	go func() {
		done <- h.Start(nil, make(chan types.InteractionEvent, 16))
	}()

	// Bring the listener up before stopping.
	dialWhenUp(t, addr).Close()

	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("first Stop = %v, want nil", err)
	}
	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("second Stop = %v, want nil", err)
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

// TestShutdownClosesInFlightConnections starts the server, dials a real
// connection, waits for the Connect event so the server has registered the
// conn, then Stops. It asserts the server-side close propagates to the
// client (Read returns an error / EOF) and that Start's accept loop and the
// handleConn goroutine exit (Start returns). This guards the goroutine/FD
// leak fix.
func TestShutdownClosesInFlightConnections(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)

	eventChan := make(chan types.InteractionEvent, 8)
	done := make(chan error, 1)
	go func() {
		done <- h.Start(nil, eventChan)
	}()

	conn := dialWhenUp(t, addr)
	defer conn.Close()

	// Wait for the server to register the connection.
	select {
	case evt := <-eventChan:
		e, ok := evt.(*Event)
		if !ok {
			t.Fatalf("got %T, want *Event", evt)
		}
		if e.action != Connect {
			t.Fatalf("first event action = %v, want Connect", e.action)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no Connect event received within 2s")
	}
	// Drain any further events so a parked send never blocks shutdown.
	go func() {
		for range eventChan {
		}
	}()

	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("Stop = %v, want nil", err)
	}

	// The server closing its side should surface to the client as EOF or
	// a connection error on the next read.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Error("client Read succeeded, want server-side close (EOF/error)")
	} else if !errors.Is(err, io.EOF) {
		// A reset or generic close is also acceptable; only a deadline
		// timeout would indicate the server never closed the conn.
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Errorf("client Read timed out (%v); server did not close the connection", err)
		}
	}

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("Start returned %v, want nil or ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return within 2s of Stop (accept/handleConn leaked)")
	}
}

// TestShutdownUnblocksParkedDispatchSend starts the handler with an
// UNBUFFERED dispatch channel that nobody reads. The Connect send from
// handleConn therefore parks. Stop closes done, which lets the parked send
// abandon so the goroutine exits and Start returns within the deadline.
func TestShutdownUnblocksParkedDispatchSend(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)

	// Unbuffered, with no consumer: handleConn's Connect send will block.
	eventChan := make(chan types.InteractionEvent)
	done := make(chan error, 1)
	go func() {
		done <- h.Start(nil, eventChan)
	}()

	conn := dialWhenUp(t, addr)
	defer conn.Close()

	// Give handleConn a beat to reach the parked send.
	time.Sleep(50 * time.Millisecond)

	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("Stop = %v, want nil", err)
	}

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("Start returned %v, want nil or ErrClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return within 3s of Stop (parked dispatch send leaked)")
	}
}
