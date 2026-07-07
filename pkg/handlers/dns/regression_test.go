package dns

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
	"github.com/miekg/dns"
)

// recordingResponseWriter implements dns.ResponseWriter and records every
// WriteMsg call so tests can assert how many replies were emitted and what
// they contained.
type recordingResponseWriter struct {
	remote net.Addr

	mu       sync.Mutex
	writes   int
	messages []*dns.Msg
}

func (f *recordingResponseWriter) LocalAddr() net.Addr  { return nil }
func (f *recordingResponseWriter) RemoteAddr() net.Addr { return f.remote }
func (f *recordingResponseWriter) WriteMsg(m *dns.Msg) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	// store a copy of the answers as written at this point in time so a
	// growing/shared slice can't retroactively change what we recorded.
	cp := *m
	cp.Answer = append([]dns.RR(nil), m.Answer...)
	f.messages = append(f.messages, &cp)
	return nil
}
func (f *recordingResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (f *recordingResponseWriter) Close() error              { return nil }
func (f *recordingResponseWriter) TsigStatus() error         { return nil }
func (f *recordingResponseWriter) TsigTimersOnly(bool)       {}
func (f *recordingResponseWriter) Hijack()                   {}

func (f *recordingResponseWriter) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

// drainEvents consumes any dispatched events so the dispatch goroutine never
// blocks during a test.
func drainEvents(ch chan types.InteractionEvent) {
	go func() {
		for range ch {
		}
	}()
}

// TestMultiQuestionSingleReply is a regression test for the bug where the mux
// handler called WriteMsg inside the question loop, emitting one reply per
// question (each progressively larger). After the fix exactly one reply is
// written, containing one A answer per question.
func TestMultiQuestionSingleReply(t *testing.T) {
	addr := freeUDPPort(t)
	h := NewHandler(map[string]string{
		"listener":   addr,
		"default_ip": "192.0.2.42",
	}).(*Handler)

	eventChan := make(chan types.InteractionEvent, 16)
	drainEvents(eventChan)
	go func() {
		_ = h.Start(nil, eventChan)
	}()
	t.Cleanup(func() { _ = h.Stop(context.Background()) })

	// Wait until the server is listening before grabbing the mux handler.
	if !waitForServer(t, h) {
		t.Fatal("dns server did not bind within deadline")
	}

	handler := serverHandler(t, h)

	req := new(dns.Msg)
	req.SetQuestion("one.example.", dns.TypeA)
	req.Question = append(req.Question,
		dns.Question{Name: "two.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		dns.Question{Name: "three.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	)

	w := &recordingResponseWriter{remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}}
	handler.ServeDNS(w, req)

	if got := w.writeCount(); got != 1 {
		t.Fatalf("WriteMsg called %d times, want exactly 1", got)
	}

	resp := w.messages[0]
	if len(resp.Answer) != len(req.Question) {
		t.Fatalf("reply has %d answers, want %d (one per question)", len(resp.Answer), len(req.Question))
	}
	for i, q := range req.Question {
		a, ok := resp.Answer[i].(*dns.A)
		if !ok {
			t.Fatalf("answer %d is %T, want *dns.A", i, resp.Answer[i])
		}
		if a.Hdr.Name != q.Name {
			t.Errorf("answer %d name = %q, want %q", i, a.Hdr.Name, q.Name)
		}
		if a.A.String() != "192.0.2.42" {
			t.Errorf("answer %d A = %s, want 192.0.2.42", i, a.A.String())
		}
	}
}

// TestInvalidDefaultIP is a regression test for the bug where an empty,
// malformed, or IPv6 default_ip produced a nil A record in every answer
// (net.ParseIP(...).To4() == nil). After the fix the handler omits A answers
// entirely, does not panic, and still returns a valid reply.
func TestInvalidDefaultIP(t *testing.T) {
	tests := []struct {
		name      string
		defaultIP string
	}{
		{"empty", ""},
		{"malformed", "not-an-ip"},
		{"ipv6", "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := freeUDPPort(t)
			h := NewHandler(map[string]string{
				"listener":   addr,
				"default_ip": tt.defaultIP,
			}).(*Handler)

			eventChan := make(chan types.InteractionEvent, 16)
			drainEvents(eventChan)
			go func() {
				_ = h.Start(nil, eventChan)
			}()
			t.Cleanup(func() { _ = h.Stop(context.Background()) })

			if !waitForServer(t, h) {
				t.Fatal("dns server did not bind within deadline")
			}

			handler := serverHandler(t, h)

			req := new(dns.Msg)
			req.SetQuestion("test.example.", dns.TypeA)

			w := &recordingResponseWriter{remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}}

			// Must not panic on a nil/non-IPv4 default_ip.
			handler.ServeDNS(w, req)

			if got := w.writeCount(); got != 1 {
				t.Fatalf("WriteMsg called %d times, want exactly 1", got)
			}
			resp := w.messages[0]
			if len(resp.Answer) != 0 {
				t.Fatalf("reply has %d answers, want 0 for invalid default_ip", len(resp.Answer))
			}
			// Still a valid reply to the query.
			if !resp.Response {
				t.Error("reply is not marked as a response")
			}
			if resp.Id != req.Id {
				t.Errorf("reply id = %d, want %d", resp.Id, req.Id)
			}
		})
	}
}

// TestStopTwiceIsIdempotent verifies Stop can be called multiple times on the
// same handler after Start without error; the second call sees a nil server
// (Stop nils h.server under lock) and returns nil.
func TestStopTwiceIsIdempotent(t *testing.T) {
	addr := freeUDPPort(t)
	h := NewHandler(map[string]string{"listener": addr, "default_ip": "1.1.1.1"}).(*Handler)

	done := make(chan error, 1)
	go func() {
		done <- h.Start(nil, make(chan types.InteractionEvent, 16))
	}()

	if !waitForServer(t, h) {
		t.Fatal("dns server did not bind within deadline")
	}

	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("first Stop = %v, want nil", err)
	}
	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("second Stop = %v, want nil", err)
	}

	select {
	case <-done:
		// Start returned; good.
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return within 2s of Stop")
	}
}

// serverHandler returns the dns.Handler the running server is using, so tests
// can drive the mux directly with a fake ResponseWriter.
func serverHandler(t *testing.T, h *Handler) dns.Handler {
	t.Helper()
	h.mu.Lock()
	srv := h.server
	h.mu.Unlock()
	if srv == nil || srv.Handler == nil {
		t.Fatal("server handler not set")
	}
	return srv.Handler
}

// waitForServer waits until the handler's server has been assigned and its
// mux handler installed.
func waitForServer(t *testing.T, h *Handler) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		srv := h.server
		h.mu.Unlock()
		if srv != nil && srv.Handler != nil {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
