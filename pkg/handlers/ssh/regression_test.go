package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
	"github.com/gliderlabs/ssh"
	cryptossh "golang.org/x/crypto/ssh"
)

// newTestSigner generates an ephemeral ed25519 SSH signer for public-key auth.
func newTestSigner(t *testing.T) cryptossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer
}

// dialAndCapture dials the SSH listener at addr using cfg (expecting auth to
// fail) and returns the first *Event dispatched by the handler. It reuses the
// retry/auth-failure approach from TestHandlerStartDispatchesPasswordAuth.
func dialAndCapture(t *testing.T, addr string, cfg *cryptossh.ClientConfig, eventChan chan types.InteractionEvent) *Event {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	var dialErr error
	for time.Now().Before(deadline) {
		client, err := cryptossh.Dial("tcp", addr, cfg)
		if err == nil {
			client.Close()
			break
		}
		dialErr = err
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
		return sshEvt
	case <-time.After(2 * time.Second):
		t.Fatal("no event received within 2s")
	}
	return nil
}

// TestPasswordAuthCapturesCredentialInRawData is a regression test for the bug
// where the attempted credential was only logged at Debug and never set on the
// event's RawData. The dispatched event's Data()/RawData must now be non-empty
// and contain both the attempted username and password.
func TestPasswordAuthCapturesCredentialInRawData(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)

	eventChan := make(chan types.InteractionEvent, 8)
	go func() {
		_ = h.Start(nil, eventChan)
	}()
	t.Cleanup(func() { _ = h.Stop(context.Background()) })

	cfg := &cryptossh.ClientConfig{
		User: "root",
		Auth: []cryptossh.AuthMethod{
			cryptossh.Password("hunter2"),
		},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	evt := dialAndCapture(t, addr, cfg, eventChan)

	if evt.action != PasswordAuth {
		t.Errorf("action = %v, want PasswordAuth", evt.action)
	}
	if len(evt.RawData) == 0 {
		t.Fatal("RawData is empty, want captured credential")
	}
	data := evt.Data()
	if data == "" {
		t.Fatal("Data() is empty, want captured credential")
	}
	if !strings.Contains(data, "root") {
		t.Errorf("Data() = %q, want to contain username %q", data, "root")
	}
	if !strings.Contains(data, "hunter2") {
		t.Errorf("Data() = %q, want to contain password %q", data, "hunter2")
	}
}

// TestPublicKeyAuthCapturesCredentialInRawData is the public-key counterpart of
// the credential-capture regression test. The dispatched event's RawData must
// contain the attempted username and the key type.
func TestPublicKeyAuthCapturesCredentialInRawData(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(map[string]string{"listener": addr}).(*Handler)

	eventChan := make(chan types.InteractionEvent, 8)
	go func() {
		_ = h.Start(nil, eventChan)
	}()
	t.Cleanup(func() { _ = h.Stop(context.Background()) })

	signer := newTestSigner(t)
	cfg := &cryptossh.ClientConfig{
		User: "operator",
		Auth: []cryptossh.AuthMethod{
			cryptossh.PublicKeys(signer),
		},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	evt := dialAndCapture(t, addr, cfg, eventChan)

	if evt.action != KeyAuth {
		t.Errorf("action = %v, want KeyAuth", evt.action)
	}
	if len(evt.RawData) == 0 {
		t.Fatal("RawData is empty, want captured credential")
	}
	data := evt.Data()
	if !strings.Contains(data, "operator") {
		t.Errorf("Data() = %q, want to contain username %q", data, "operator")
	}
	if !strings.Contains(data, signer.PublicKey().Type()) {
		t.Errorf("Data() = %q, want to contain key-type %q", data, signer.PublicKey().Type())
	}
}

// TestPasswordAuthEventDetails is a regression test for the new Details()
// method on *Event. It must produce an SSH-specific string containing the
// username and "SSH:" rather than the embedded BaseEvent's "Default Event".
func TestPasswordAuthEventDetails(t *testing.T) {
	ctx := &fakeSSHContext{
		user:          "carol",
		remoteAddr:    &net.TCPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 4242},
		clientVersion: "SSH-2.0-Test",
	}

	evt := NewEvent(ctx, PasswordAuth)
	details := evt.Details()

	if details == "Default Event" {
		t.Fatalf("Details() = %q, want SSH-specific details, not the BaseEvent default", details)
	}
	if !strings.Contains(details, "SSH:") {
		t.Errorf("Details() = %q, want to contain %q", details, "SSH:")
	}
	if !strings.Contains(details, "carol") {
		t.Errorf("Details() = %q, want to contain username %q", details, "carol")
	}
	if !strings.Contains(details, "PasswordAuth") {
		t.Errorf("Details() = %q, want to contain action %q", details, "PasswordAuth")
	}
}

// fakeSSHContext is a minimal ssh.Context implementation for constructing an
// *Event without standing up a real SSH server.
type fakeSSHContext struct {
	context.Context
	sync.Mutex
	user          string
	remoteAddr    net.Addr
	clientVersion string
}

func (c *fakeSSHContext) User() string                    { return c.user }
func (c *fakeSSHContext) SessionID() string               { return "test-session" }
func (c *fakeSSHContext) ClientVersion() string           { return c.clientVersion }
func (c *fakeSSHContext) ServerVersion() string           { return "SSH-2.0-Server" }
func (c *fakeSSHContext) RemoteAddr() net.Addr            { return c.remoteAddr }
func (c *fakeSSHContext) LocalAddr() net.Addr             { return &net.TCPAddr{} }
func (c *fakeSSHContext) Permissions() *ssh.Permissions   { return &ssh.Permissions{} }
func (c *fakeSSHContext) SetValue(key, value interface{}) {}
