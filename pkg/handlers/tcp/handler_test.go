package tcp

import (
	"net"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
)

func TestActionString(t *testing.T) {
	tests := []struct {
		action Action
		want   string
	}{
		{Connect, "Connection"},
		{DataRecv, "Data"},
		{Disconnect, "Disconnection"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.action.String(); got != tc.want {
				t.Errorf("Action(%d).String() = %q, want %q", tc.action, got, tc.want)
			}
		})
	}
}

type fakeAddr struct{ s string }

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return a.s }

type fakeConn struct {
	net.Conn
	remote net.Addr
}

func (f fakeConn) RemoteAddr() net.Addr { return f.remote }

func TestNewEventParsesRemoteAddress(t *testing.T) {
	conn := fakeConn{remote: fakeAddr{s: "10.20.30.40:54321"}}

	e := NewEvent(conn, Connect, nil)

	if e.RemoteAddr != "10.20.30.40" {
		t.Errorf("RemoteAddr = %q, want %q", e.RemoteAddr, "10.20.30.40")
	}
	if e.RemotePortNumber != 54321 {
		t.Errorf("RemotePortNumber = %d, want 54321", e.RemotePortNumber)
	}
	if e.action != Connect {
		t.Errorf("action = %v, want Connect", e.action)
	}
}

func TestEventDetails(t *testing.T) {
	conn := fakeConn{remote: fakeAddr{s: "1.2.3.4:9999"}}
	e := NewEvent(conn, DataRecv, nil)

	got := e.Details()
	want := "TCP Interaction Event: 1.2.3.4 9999 Data"
	if got != want {
		t.Errorf("Details() = %q, want %q", got, want)
	}
}

func TestNewHandler(t *testing.T) {
	h := NewHandler(map[string]string{"listener": "127.0.0.1:1234"})

	if h.Name() != "TCP" {
		t.Errorf("Name() = %q, want TCP", h.Name())
	}

	concrete, ok := h.(*Handler)
	if !ok {
		t.Fatalf("NewHandler returned %T, want *Handler", h)
	}
	if concrete.Listener != "127.0.0.1:1234" {
		t.Errorf("Listener = %q, want 127.0.0.1:1234", concrete.Listener)
	}
}

// freePort reserves a TCP port on loopback by listening then closing,
// returning the address string. This is racy in principle but reliable
// enough for a single-test integration check.
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

func TestHandlerStartDispatchesConnect(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)

	eventChan := make(chan types.InteractionEvent, 8)
	go func() {
		_ = h.Start(nil, eventChan)
	}()

	// Dial with retries until the listener is up.
	var conn net.Conn
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.Dial("tcp", addr)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial handler: %v", err)
	}
	defer conn.Close()

	select {
	case evt := <-eventChan:
		tcpEvt, ok := evt.(*Event)
		if !ok {
			t.Fatalf("got %T, want *Event", evt)
		}
		if tcpEvt.action != Connect {
			t.Errorf("action = %v, want Connect", tcpEvt.action)
		}
		if tcpEvt.RemoteAddr == "" {
			t.Error("RemoteAddr should be populated on the connect event")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no Connect event received within 2s")
	}
}
