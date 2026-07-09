package smb

import (
	"net"
	"testing"
)

func TestFilterString(t *testing.T) {
	c := &fakeConn{remote: "10.0.0.5:445"}

	auth := NewEvent(c, Auth, []byte("alice::CORP:..."))
	auth.Account = "CORP\\alice"
	if got := auth.FilterString(); got != "SMB Auth CORP\\alice from 10.0.0.5" {
		t.Errorf("Auth FilterString = %q", got)
	}

	conn := NewEvent(c, Connect, nil)
	if got := conn.FilterString(); got != "SMB Connect from 10.0.0.5" {
		t.Errorf("Connect FilterString = %q", got)
	}
}

// fakeConn is a minimal net.Conn stand-in exposing a RemoteAddr.
type fakeConn struct {
	net.Conn
	remote string
}

func (f *fakeConn) RemoteAddr() net.Addr { return fakeAddr(f.remote) }

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }
