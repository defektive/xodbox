package ssh

import (
	"net"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
	cryptossh "golang.org/x/crypto/ssh"
)

func TestActionString(t *testing.T) {
	tests := []struct {
		action Action
		want   string
	}{
		{PasswordAuth, "PasswordAuth"},
		{KeyAuth, "KeyAuth"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.action.String(); got != tc.want {
				t.Errorf("Action(%d).String() = %q, want %q", tc.action, got, tc.want)
			}
		})
	}
}

func TestNewHandlerListenerDefault(t *testing.T) {
	h := NewHandler(map[string]string{}).(*Handler)
	if h.Listener != ":22" {
		t.Errorf("default Listener = %q, want :22", h.Listener)
	}
	if h.Name() != "SSH" {
		t.Errorf("Name() = %q, want SSH", h.Name())
	}
}

func TestNewHandlerListenerOverride(t *testing.T) {
	h := NewHandler(map[string]string{"listener": "127.0.0.1:2222"}).(*Handler)
	if h.Listener != "127.0.0.1:2222" {
		t.Errorf("Listener = %q, want 127.0.0.1:2222", h.Listener)
	}
}

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

func TestHandlerStartDispatchesPasswordAuth(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)

	eventChan := make(chan types.InteractionEvent, 8)
	go func() {
		_ = h.Start(nil, eventChan)
	}()

	cfg := &cryptossh.ClientConfig{
		User: "alice",
		Auth: []cryptossh.AuthMethod{
			cryptossh.Password("hunter2"),
		},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	// Dial with retries until the SSH listener is up. We expect auth to
	// fail (the handler always returns false) — what we care about is that
	// the password-auth callback fired and produced an event.
	deadline := time.Now().Add(3 * time.Second)
	var dialErr error
	for time.Now().Before(deadline) {
		client, err := cryptossh.Dial("tcp", addr, cfg)
		if err == nil {
			client.Close()
			break
		}
		dialErr = err
		// "unable to authenticate" means the listener accepted the
		// connection and ran our auth callback — exactly what we want.
		if isAuthFailure(err) {
			dialErr = nil
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if dialErr != nil {
		t.Fatalf("ssh dial: %v", dialErr)
	}

	select {
	case evt := <-eventChan:
		sshEvt, ok := evt.(*Event)
		if !ok {
			t.Fatalf("got %T, want *Event", evt)
		}
		if sshEvt.action != PasswordAuth {
			t.Errorf("action = %v, want PasswordAuth", sshEvt.action)
		}
		if sshEvt.user != "alice" {
			t.Errorf("user = %q, want alice", sshEvt.user)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no PasswordAuth event received within 2s")
	}
}

func isAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, marker := range []string{"unable to authenticate", "no supported methods remain"} {
		if containsFold(msg, marker) {
			return true
		}
	}
	return false
}

func containsFold(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if equalFold(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
