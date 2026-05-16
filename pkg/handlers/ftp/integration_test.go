package ftp

import (
	"net"
	"net/textproto"
	"strings"
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

// Walks the basic FTP server up to USER/PASS using net/textproto so we can
// observe the server greeting (which exercises ClientConnected) and an auth
// failure (which exercises AuthUser's "no credentials configured" path).
func TestHandlerStartGreetsAndAuthsAnonymously(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)

	eventChan := make(chan types.InteractionEvent, 16)
	go func() {
		_ = h.Start(nil, eventChan)
	}()

	// Wait for the listener to come up.
	deadline := time.Now().Add(3 * time.Second)
	var conn net.Conn
	var err error
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial ftp: %v", err)
	}
	defer conn.Close()

	tp := textproto.NewConn(conn)

	// Server greeting (2xx).
	code, msg, err := tp.ReadResponse(2)
	if err != nil {
		t.Fatalf("greeting: %v (code=%d msg=%q)", err, code, msg)
	}
	if !strings.Contains(msg, "FTP Server") {
		t.Errorf("greeting message = %q, want substring 'FTP Server'", msg)
	}

	// USER step — server should accept and ask for password (3xx).
	if err := tp.PrintfLine("USER anonymous"); err != nil {
		t.Fatalf("USER: %v", err)
	}
	if _, _, err := tp.ReadResponse(3); err != nil {
		t.Fatalf("USER response: %v", err)
	}

	// PASS step — with no credentials configured AuthUser rejects (5xx).
	if err := tp.PrintfLine("PASS anonymous"); err != nil {
		t.Fatalf("PASS: %v", err)
	}
	if _, _, err := tp.ReadResponse(5); err != nil {
		t.Fatalf("PASS expected 5xx, got: %v", err)
	}

	// QUIT to flush.
	_ = tp.PrintfLine("QUIT")
}
