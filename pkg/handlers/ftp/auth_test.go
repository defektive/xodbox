package ftp

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
	ftpserver "github.com/fclairamb/ftpserverlib"
)

// fakeClientContext implements ftpserver.ClientContext with the minimum
// behaviour the FTP handler exercises: identity (ID), RemoteAddr, plus
// the no-ops the server drivers call on connect/disconnect.
type fakeClientContext struct {
	id     uint32
	remote net.Addr
	extra  any
	debug  bool
}

func (f *fakeClientContext) Path() string                                  { return "/" }
func (f *fakeClientContext) SetPath(string)                                {}
func (f *fakeClientContext) SetListPath(string)                            {}
func (f *fakeClientContext) SetDebug(d bool)                               { f.debug = d }
func (f *fakeClientContext) Debug() bool                                   { return f.debug }
func (f *fakeClientContext) ID() uint32                                    { return f.id }
func (f *fakeClientContext) RemoteAddr() net.Addr                          { return f.remote }
func (f *fakeClientContext) LocalAddr() net.Addr                           { return f.remote }
func (f *fakeClientContext) GetClientVersion() string                      { return "fake/1" }
func (f *fakeClientContext) Close() error                                  { return nil }
func (f *fakeClientContext) HasTLSForControl() bool                        { return false }
func (f *fakeClientContext) HasTLSForTransfers() bool                      { return false }
func (f *fakeClientContext) GetLastCommand() string                        { return "" }
func (f *fakeClientContext) GetLastDataChannel() ftpserver.DataChannel     { return 0 }
func (f *fakeClientContext) SetTLSRequirement(ftpserver.TLSRequirement) error {
	return nil
}
func (f *fakeClientContext) SetExtra(x any) { f.extra = x }
func (f *fakeClientContext) Extra() any     { return f.extra }

func TestClientConnectedAppendsAndReturnsServerName(t *testing.T) {
	d := &SimpleServerDriver{
		ServerName: "honeypot",
		Debug:      true, // verify ClientConnected propagates this to the context
	}
	cc := &fakeClientContext{
		id:     42,
		remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999},
	}

	greeting, err := d.ClientConnected(cc)
	if err != nil {
		t.Fatalf("ClientConnected err: %v", err)
	}
	if greeting != "honeypot" {
		t.Errorf("greeting = %q, want honeypot", greeting)
	}
	if len(d.Clients) != 1 || d.Clients[0].ID() != 42 {
		t.Errorf("driver.Clients should track the new client, got %+v", d.Clients)
	}
	if !cc.debug {
		t.Error("ClientConnected should have set the context's Debug flag")
	}
	if cc.extra != cc.id {
		t.Errorf("Extra should be set to client ID; got %v want %v", cc.extra, cc.id)
	}
}

func TestClientConnectedRefuses(t *testing.T) {
	d := &SimpleServerDriver{
		ServerName:     "honeypot",
		CloseOnConnect: true,
	}
	cc := &fakeClientContext{id: 7, remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8888}}

	_, err := d.ClientConnected(cc)
	if err == nil {
		t.Error("expected error when CloseOnConnect is true")
	}
}

func TestClientDisconnectedRemovesClient(t *testing.T) {
	d := &SimpleServerDriver{ServerName: "x"}
	a := &fakeClientContext{id: 1, remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}}
	b := &fakeClientContext{id: 2, remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}}

	if _, err := d.ClientConnected(a); err != nil {
		t.Fatalf("connect a: %v", err)
	}
	if _, err := d.ClientConnected(b); err != nil {
		t.Fatalf("connect b: %v", err)
	}

	d.ClientDisconnected(a)
	if len(d.Clients) != 1 {
		t.Fatalf("len(Clients) = %d after disconnect, want 1", len(d.Clients))
	}
	if d.Clients[0].ID() != 2 {
		t.Errorf("remaining client ID = %d, want 2", d.Clients[0].ID())
	}
}

func TestClientDisconnectedUnknownIDIsNoOp(t *testing.T) {
	d := &SimpleServerDriver{ServerName: "x"}
	d.Clients = []ftpserver.ClientContext{
		&fakeClientContext{id: 100, remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}},
	}

	d.ClientDisconnected(&fakeClientContext{id: 999})
	if len(d.Clients) != 1 {
		t.Errorf("len(Clients) = %d, want 1 (unknown ID should not mutate)", len(d.Clients))
	}
}

func TestAuthUserSuccessDispatches(t *testing.T) {
	h := &Handler{
		name:            "FTP",
		dispatchChannel: make(chan types.InteractionEvent, 4),
	}
	d := &SimpleServerDriver{
		Handler: h,
		fs:      nil,
		Credentials: []*AuthUser{
			{Username: "alice", Password: "hunter2", UserID: 1000, GroupID: 1000},
		},
	}

	cc := &fakeClientContext{id: 1, remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 21}}
	driver, err := d.AuthUser(cc, "alice", "hunter2")
	if err != nil {
		t.Fatalf("AuthUser err: %v", err)
	}

	cd, ok := driver.(*SimpleClientDriver)
	if !ok {
		t.Fatalf("got %T, want *SimpleClientDriver", driver)
	}
	if cd.User.Username != "alice" {
		t.Errorf("driver.User.Username = %q, want alice", cd.User.Username)
	}

	select {
	case evt := <-h.dispatchChannel:
		ftpEvt, ok := evt.(*Event)
		if !ok {
			t.Fatalf("got %T, want *Event", evt)
		}
		if ftpEvt.action != AuthSuccess {
			t.Errorf("action = %v, want AuthSuccess", ftpEvt.action)
		}
	case <-time.After(time.Second):
		t.Fatal("no AuthSuccess event dispatched")
	}
}

func TestAuthUserRejectsBadPassword(t *testing.T) {
	h := &Handler{
		name:            "FTP",
		dispatchChannel: make(chan types.InteractionEvent, 4),
	}
	d := &SimpleServerDriver{
		Handler:     h,
		Credentials: []*AuthUser{{Username: "alice", Password: "hunter2"}},
	}

	cc := &fakeClientContext{id: 1, remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 21}}
	_, err := d.AuthUser(cc, "alice", "wrong")
	if err == nil {
		t.Error("expected error for bad password")
	}

	// No event should have been dispatched.
	select {
	case <-h.dispatchChannel:
		t.Error("did not expect any event on auth failure")
	case <-time.After(50 * time.Millisecond):
		// good
	}
}

func TestPreAuthUserSetsTLSRequirement(t *testing.T) {
	// SetTLSRequirement is a no-op on our fake; the driver passes the
	// configured requirement through. We just verify it doesn't error.
	d := &SimpleServerDriver{TLSRequirement: ftpserver.ClearOrEncrypted}
	cc := &fakeClientContext{}
	if err := d.PreAuthUser(cc, "alice"); err != nil {
		t.Errorf("PreAuthUser err = %v, want nil", err)
	}
}

func TestVerifyConnectionDispatchesByTLSReply(t *testing.T) {
	tests := []struct {
		name    string
		reply   tlsVerificationReply
		wantErr bool
		wantDrv bool
	}{
		{"failed", tlsVerificationFailed, true, false},
		{"authenticated", tlsVerificationAuthenticated, false, true},
		{"ok", tlsVerificationOK, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &SimpleServerDriver{TLSVerificationReply: tc.reply}
			cc := &fakeClientContext{}
			drv, err := d.VerifyConnection(cc, "", nil)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantDrv && drv == nil {
				t.Error("expected driver, got nil")
			}
			if !tc.wantDrv && drv != nil {
				t.Errorf("expected nil driver, got %T", drv)
			}
		})
	}
}

func TestSimpleClientDriverDispatchEvent(t *testing.T) {
	h := &Handler{
		name:            "FTP",
		dispatchChannel: make(chan types.InteractionEvent, 4),
	}
	cd := &SimpleClientDriver{
		Handler: h,
		Client:  &fakeClientContext{remote: &net.TCPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 21}},
	}
	cd.DispatchEvent(FileOpen)

	select {
	case evt := <-h.dispatchChannel:
		e, ok := evt.(*Event)
		if !ok {
			t.Fatalf("got %T, want *Event", evt)
		}
		if e.action != FileOpen {
			t.Errorf("action = %v, want FileOpen", e.action)
		}
		if e.RemoteAddr != "8.8.8.8" {
			t.Errorf("RemoteAddr = %q, want 8.8.8.8", e.RemoteAddr)
		}
	case <-time.After(time.Second):
		t.Fatal("no event dispatched")
	}

	// Drain & relax: ensure atomic.LoadInt32 wasn't needed (no goroutines)
	_ = atomic.LoadInt32(new(int32))
}
