package smtp

import (
	"context"
	"fmt"
	"net"
	netsmtp "net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
)

// waitForListener dials the address until the server accepts a connection or
// the deadline elapses. It mirrors the readiness loop used in the existing
// integration test.
func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("smtp listener at %s never became ready", addr)
}

// TestDataCapturesBody is a regression test for the bug where
// SMTPSession.Data(r) ignored its io.Reader and silently dropped the message
// body. It drives the real *smtp.Server end-to-end (so the real Data() method
// runs) and asserts the dispatched *Event carries the message body on RawData.
func TestDataCapturesBody(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)

	eventChan := make(chan types.InteractionEvent, 16)
	go func() {
		_ = h.Start(nil, eventChan)
	}()
	defer h.Stop(context.Background())

	waitForListener(t, addr)

	const body = "Subject: hi\r\n\r\nhello world"

	c, err := netsmtp.Dial(addr)
	if err != nil {
		t.Fatalf("smtp.Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello("test-client.example"); err != nil {
		t.Fatalf("HELO: %v", err)
	}
	if err := c.Mail("from@example.com"); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	if err := c.Rcpt("to@example.com"); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatalf("DATA: %v", err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close data writer: %v", err)
	}
	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT: %v", err)
	}

	// The Data event is dispatched asynchronously (Event.Dispatch spawns a
	// goroutine), so collect from the channel with a timeout until we see it.
	timeout := time.After(3 * time.Second)
	for {
		select {
		case evt := <-eventChan:
			e, ok := evt.(*Event)
			if !ok {
				t.Fatalf("expected *Event, got %T", evt)
			}
			if e.action != Data {
				continue
			}
			// The real SMTP DATA exchange appends a trailing CRLF before
			// the terminating dot, so the captured body is the message we
			// sent followed by "\r\n". The regression we guard against is
			// the body being dropped entirely (empty); assert it is present
			// and intact rather than requiring byte-exact equality.
			got := e.Data()
			if got == "" {
				t.Fatalf("Data event body is empty; message body was dropped")
			}
			if !strings.HasPrefix(got, body) {
				t.Fatalf("Data event body = %q, want it to start with %q", got, body)
			}
			if !strings.Contains(got, "hello world") {
				t.Fatalf("Data event body = %q, want it to contain %q", got, "hello world")
			}
			// RawData and Data() must agree.
			if string(e.RawData) != got {
				t.Fatalf("RawData (%q) != Data() (%q)", string(e.RawData), got)
			}
			return
		case <-timeout:
			t.Fatal("did not receive a Data event with the captured body within 3s")
		}
	}
}

// TestDetailsFormat is a regression test for the newly added Details() method.
// Previously the promoted BaseEvent.Details() returned the generic
// "Default Event"; the SMTP Event now formats a protocol-specific string.
func TestDetailsFormat(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action Action
	}{
		{"Data", Data},
		{"Mail", Mail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &Event{
				BaseEvent: &types.BaseEvent{RemoteAddr: "203.0.113.5"},
				action:    tc.action,
			}
			want := fmt.Sprintf("SMTP: %s from %s", tc.action, "203.0.113.5")
			if got := e.Details(); got != want {
				t.Errorf("Details() = %q, want %q", got, want)
			}
			if got := e.Details(); got == "Default Event" {
				t.Errorf("Details() returned generic %q; expected SMTP-specific string", got)
			}
		})
	}
}

// TestDoubleStopIsIdempotent is a regression test for Handler.Stop nil-ing
// h.server. After a Start, calling Stop twice must both return nil rather than
// panicking or double-shutting-down the server.
func TestDoubleStopIsIdempotent(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)

	done := make(chan error, 1)
	go func() {
		done <- h.Start(nil, make(chan types.InteractionEvent, 16))
	}()

	waitForListener(t, addr)

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
