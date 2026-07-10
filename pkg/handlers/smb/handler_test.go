package smb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
)

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestStopBeforeStartIsNoOp(t *testing.T) {
	h := NewHandler(map[string]string{"listener": "127.0.0.1:0"}).(*Handler)
	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("Stop before Start = %v, want nil", err)
	}
}

func TestDefaultListener(t *testing.T) {
	h := NewHandler(map[string]string{}).(*Handler)
	if h.Listener != ":445" {
		t.Errorf("default listener = %q, want :445", h.Listener)
	}
	if h.TargetName != defaultTargetName {
		t.Errorf("default target name = %q, want %q", h.TargetName, defaultTargetName)
	}
}

func TestTargetNameParsedFromConfig(t *testing.T) {
	h := NewHandler(map[string]string{"target_name": "CORP-FS01"}).(*Handler)
	if h.TargetName != "CORP-FS01" {
		t.Errorf("target name = %q, want CORP-FS01", h.TargetName)
	}
}

func TestAuthEventInteraction(t *testing.T) {
	nt := append(bytes.Repeat([]byte{0xEE}, 16), 0x01, 0x02, 0x03, 0x04)
	info, err := parseAuthenticate(buildAuthenticate("CORP", "carol", nt))
	if err != nil {
		t.Fatalf("parseAuthenticate: %v", err)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Build the event exactly as the handler does on capture; central
	// persistence (pkg/xodbox) stores whatever Interaction() returns.
	ev := NewEvent(server, Auth, []byte(info.HashcatLine()))
	ev.Account = info.Account()

	got := ev.Interaction()
	if got == nil {
		t.Fatal("Auth event produced no Interaction")
	}
	if got.Handler != "smb" || got.Protocol != "smb" || got.RequestType != "Auth" {
		t.Errorf("Handler/Protocol/RequestType = %q/%q/%q, want smb/smb/Auth", got.Handler, got.Protocol, got.RequestType)
	}
	if got.RequestTarget != "CORP\\carol" {
		t.Errorf("RequestTarget = %q, want CORP\\carol", got.RequestTarget)
	}
	if !bytes.HasPrefix(got.Data, []byte("carol::CORP:")) {
		t.Errorf("Data = %q, want hashcat line", got.Data)
	}
}

func TestStopUnblocksStart(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)

	done := make(chan error, 1)
	go func() { done <- h.Start(nil, make(chan types.InteractionEvent, 16)) }()
	waitListening(t, addr)

	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("Stop = %v, want nil", err)
	}
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("Start returned %v, want nil or ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return within 2s of Stop")
	}
}

// smb2Request builds a minimal SMB2 request: a 64-byte header with the
// given command followed by an arbitrary body. The fake server only reads
// the command, message id, and (for session setup) the security buffer.
func smb2Request(command uint16, messageID uint64, body []byte) []byte {
	h := make([]byte, 64)
	copy(h[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(h[4:], 64)
	binary.LittleEndian.PutUint16(h[12:], command)
	binary.LittleEndian.PutUint64(h[24:], messageID)
	return append(h, body...)
}

// sessionSetupRequest wraps secBuf in an SMB2 SESSION_SETUP request body.
func sessionSetupRequest(messageID uint64, secBuf []byte) []byte {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:], 25) // StructureSize
	secOff := uint16(64 + 24)
	binary.LittleEndian.PutUint16(body[12:], secOff)
	binary.LittleEndian.PutUint16(body[14:], uint16(len(secBuf)))
	body = append(body, secBuf...)
	return smb2Request(cmdSessionSetup, messageID, body)
}

func ntlmNegotiateMessage() []byte {
	m := make([]byte, 16)
	copy(m[0:], ntlmSignature)
	binary.LittleEndian.PutUint32(m[8:], ntlmNegotiate)
	binary.LittleEndian.PutUint32(m[12:], negotiateUnicode|negotiateNTLM)
	return m
}

// TestCaptureFlow drives a full negotiate -> challenge -> authenticate
// exchange against the live handler and asserts the NetNTLMv2 hash is
// captured and dispatched.
func TestCaptureFlow(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)
	events := make(chan types.InteractionEvent, 16)
	go func() { _ = h.Start(nil, events) }()
	defer h.Stop(context.Background())
	waitListening(t, addr)

	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	// 1. SMB2 NEGOTIATE offering a Windows-like dialect spread; the server
	// must answer with the best it supports (2.1).
	if err := writePacket(c, negotiateRequest(0x0202, 0x0210, 0x0300, 0x0311)); err != nil {
		t.Fatalf("write negotiate: %v", err)
	}
	negResp, err := readPacket(c)
	if err != nil {
		t.Fatalf("read negotiate response: %v", err)
	}
	if d := binary.LittleEndian.Uint16(negResp[64+4:]); d != dialect0210 {
		t.Fatalf("negotiated dialect = %#04x, want %#04x", d, dialect0210)
	}

	// 2. SESSION_SETUP carrying NTLMSSP NEGOTIATE -> expect a CHALLENGE.
	if err := writePacket(c, sessionSetupRequest(1, ntlmNegotiateMessage())); err != nil {
		t.Fatalf("write session setup 1: %v", err)
	}
	resp, err := readPacket(c)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	challenge := findNTLMSSP(resp)
	if ntlmMessageType(challenge) != ntlmChallenge {
		t.Fatalf("expected NTLMSSP CHALLENGE in response, got type %d", ntlmMessageType(challenge))
	}

	// 3. SESSION_SETUP carrying NTLMSSP AUTHENTICATE.
	ntProof := bytes.Repeat([]byte{0xCD}, 16)
	blob := []byte{0x01, 0x01, 0xca, 0xfe}
	nt := append(append([]byte{}, ntProof...), blob...)
	auth := buildAuthenticate("CORP", "alice", nt)
	if err := writePacket(c, sessionSetupRequest(2, auth)); err != nil {
		t.Fatalf("write session setup 2: %v", err)
	}
	// Server answers with a logon failure; drain it.
	_, _ = readPacket(c)

	got := waitForAuth(t, events)
	if got.Account != "CORP\\alice" {
		t.Errorf("Account = %q, want CORP\\alice", got.Account)
	}
	if !bytes.Contains([]byte(got.Data()), []byte("alice::CORP:")) {
		t.Errorf("captured data missing hashcat line: %q", got.Data())
	}
}

func waitForAuth(t *testing.T, events <-chan types.InteractionEvent) *Event {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case e := <-events:
			if ev, ok := e.(*Event); ok && ev.action == Auth {
				return ev
			}
		case <-deadline:
			t.Fatal("no Auth event within 3s")
		}
	}
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener %s never came up", addr)
}
