package types

import (
	"testing"
	"time"
)

func TestBaseEventGetters(t *testing.T) {
	e := &BaseEvent{
		RemoteAddr:       "10.0.0.1",
		RemotePortNumber: 4242,
		UserAgentString:  "curl/8.0",
		RawData:          []byte("hello world"),
	}

	if got := e.Details(); got != "Default Event" {
		t.Errorf("Details() = %q, want %q", got, "Default Event")
	}
	if got := e.RemoteIP(); got != "10.0.0.1" {
		t.Errorf("RemoteIP() = %q, want %q", got, "10.0.0.1")
	}
	if got := e.RemotePort(); got != 4242 {
		t.Errorf("RemotePort() = %d, want %d", got, 4242)
	}
	if got := e.UserAgent(); got != "curl/8.0" {
		t.Errorf("UserAgent() = %q, want %q", got, "curl/8.0")
	}
	if got := e.Data(); got != "hello world" {
		t.Errorf("Data() = %q, want %q", got, "hello world")
	}
}

func TestBaseEventZeroValue(t *testing.T) {
	e := &BaseEvent{}
	if e.RemoteIP() != "" {
		t.Errorf("zero RemoteIP() = %q, want empty", e.RemoteIP())
	}
	if e.RemotePort() != 0 {
		t.Errorf("zero RemotePort() = %d, want 0", e.RemotePort())
	}
	if e.UserAgent() != "" {
		t.Errorf("zero UserAgent() = %q, want empty", e.UserAgent())
	}
	if e.Data() != "" {
		t.Errorf("zero Data() = %q, want empty", e.Data())
	}
}

func TestBaseEventDispatch(t *testing.T) {
	e := &BaseEvent{RemoteAddr: "1.1.1.1"}
	ch := make(chan InteractionEvent, 1)

	e.Dispatch(ch)

	select {
	case got := <-ch:
		if got.RemoteIP() != "1.1.1.1" {
			t.Errorf("dispatched event RemoteIP() = %q, want %q", got.RemoteIP(), "1.1.1.1")
		}
	case <-time.After(time.Second):
		t.Fatal("Dispatch did not deliver event within 1s")
	}
}

func TestBaseEventImplementsInteractionEvent(t *testing.T) {
	var _ InteractionEvent = (*BaseEvent)(nil)
}
