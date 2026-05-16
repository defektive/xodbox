package ftp

import (
	"testing"
)

func TestActionString(t *testing.T) {
	tests := []struct {
		action Action
		want   string
	}{
		{AuthSuccess, "AuthSuccess"},
		{AuthFail, "AuthFail"},
		{Logout, "Logout"},
		{ListFiles, "ListFiles"},
		{FileOpen, "FileOpen"},
		{FileRead, "FileRead"},
		{FileWrite, "FileWrite"},
		{FileReadDir, "FileReadDir"},
		{FileDelete, "FileDelete"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.action.String(); got != tc.want {
				t.Errorf("Action(%d).String() = %q, want %q", tc.action, got, tc.want)
			}
		})
	}
}

func TestNewEvent(t *testing.T) {
	e := NewEvent("10.0.0.5:21", AuthFail)

	if e.RemoteAddr != "10.0.0.5" {
		t.Errorf("RemoteAddr = %q, want 10.0.0.5", e.RemoteAddr)
	}
	if e.RemotePortNumber != 21 {
		t.Errorf("RemotePortNumber = %d, want 21", e.RemotePortNumber)
	}
	if e.action != AuthFail {
		t.Errorf("action = %v, want AuthFail", e.action)
	}
}

func TestEventDetails(t *testing.T) {
	e := NewEvent("192.168.1.10:21", AuthSuccess)
	want := "FTP: event from 192.168.1.10"
	if got := e.Details(); got != want {
		t.Errorf("Details() = %q, want %q", got, want)
	}
}
