package smtp

import (
	"net"
	"net/smtp"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
)

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close reservation: %v", err)
	}
	return addr
}

func TestHandlerNameAndConstruction(t *testing.T) {
	h := NewHandler(map[string]string{"listener": "127.0.0.1:2525"}).(*Handler)
	if h.Name() != "SMTP" {
		t.Errorf("Name() = %q, want SMTP", h.Name())
	}
	if h.Listener != "127.0.0.1:2525" {
		t.Errorf("Listener = %q", h.Listener)
	}
}

func TestHandlerStartDispatchesMailAndRcpt(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)

	eventChan := make(chan types.InteractionEvent, 16)
	go func() {
		_ = h.Start(nil, eventChan)
	}()

	// Wait for listener readiness by dialing TCP.
	deadline := time.Now().Add(3 * time.Second)
	var conn net.Conn
	var err error
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial smtp: %v", err)
	}

	c, err := smtp.Dial(addr)
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
	if err := c.Reset(); err != nil {
		t.Fatalf("RSET: %v", err)
	}
	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT: %v", err)
	}

	// We should have received Mail, Rcpt, Reset, Logout events at least.
	seen := map[Action]bool{}
	timeout := time.After(2 * time.Second)
collect:
	for {
		select {
		case evt := <-eventChan:
			e, ok := evt.(*Event)
			if !ok {
				t.Fatalf("expected *Event, got %T", evt)
			}
			seen[e.action] = true
			if seen[Mail] && seen[Rcpt] && seen[Reset] && seen[Logout] {
				break collect
			}
		case <-timeout:
			break collect
		}
	}

	for _, want := range []Action{Mail, Rcpt, Reset, Logout} {
		if !seen[want] {
			t.Errorf("expected %s event, did not receive one (seen=%v)", want, seen)
		}
	}
}
