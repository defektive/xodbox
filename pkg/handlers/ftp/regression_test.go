package ftp

import (
	"net"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"
)

// newDispatchingClientDriver builds a SimpleClientDriver wired with a Handler
// (buffered dispatchChannel) and a Client context, plus its mem FS — so that
// testFile.Read/Write can dispatch events without nil-dereferencing.
func newDispatchingClientDriver(t *testing.T) (*SimpleClientDriver, afero.Fs, chan types.InteractionEvent) {
	t.Helper()
	ch := make(chan types.InteractionEvent, 4)
	h := &Handler{name: "FTP", dispatchChannel: ch}
	fs := afero.NewMemMapFs()
	cd := &SimpleClientDriver{
		Client:  &fakeClientContext{remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 21}},
		Handler: h,
		Fs:      fs,
	}
	return cd, fs, ch
}

// recvEvent waits for an Event of the given action on ch.
func recvEvent(t *testing.T, ch chan types.InteractionEvent, want Action) {
	t.Helper()
	select {
	case evt := <-ch:
		e, ok := evt.(*Event)
		if !ok {
			t.Fatalf("got %T, want *Event", evt)
		}
		if e.action != want {
			t.Errorf("action = %v, want %v", e.action, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("no %v event dispatched", want)
	}
}

// Regression 1: SimpleClientDriver.Open() must set the Client field so that
// Read/Readdir on the returned *testFile do not nil-dereference
// f.Client.DispatchEvent.
func TestOpenSetsClientAndReadDoesNotPanic(t *testing.T) {
	cd, fs, ch := newDispatchingClientDriver(t)

	content := []byte("payload")
	if err := afero.WriteFile(fs, "/seed", content, 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	f, err := cd.Open("/seed")
	if err != nil {
		t.Fatalf("Open err: %v", err)
	}
	defer f.Close()

	tf, ok := f.(*testFile)
	if !ok {
		t.Fatalf("Open returned %T, want *testFile", f)
	}
	if tf.Client == nil {
		t.Fatal("Open returned a *testFile with nil Client (would panic on Read)")
	}

	// Read must not panic and must return the seeded bytes.
	out := make([]byte, len(content))
	n, err := tf.Read(out)
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if n != len(content) {
		t.Errorf("Read n = %d, want %d", n, len(content))
	}
	if string(out[:n]) != string(content) {
		t.Errorf("Read = %q, want %q", out[:n], content)
	}

	recvEvent(t, ch, FileRead)
}

// Regression 2: testFile.Write must write through to the underlying file
// (no longer unconditionally failing) and must do so without the old 500ms
// sleep, while dispatching a FileWrite event.
func TestWriteWritesThroughAndDispatches(t *testing.T) {
	cd, fs, ch := newDispatchingClientDriver(t)

	if err := afero.WriteFile(fs, "/dst", []byte{}, 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	f, err := cd.OpenFile("/dst", 0o2 /* O_RDWR */, 0o644)
	if err != nil {
		t.Fatalf("OpenFile err: %v", err)
	}

	payload := []byte("uploaded-bytes")

	start := time.Now()
	n, err := f.Write(payload)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Write err: %v, want nil", err)
	}
	if n != len(payload) {
		t.Errorf("Write n = %d, want %d", n, len(payload))
	}
	if elapsed >= 200*time.Millisecond {
		t.Errorf("Write took %v, want < 200ms (no sleep)", elapsed)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("Close err: %v", err)
	}

	// Bytes must be persisted in the FS.
	got, err := afero.ReadFile(fs, "/dst")
	if err != nil {
		t.Fatalf("ReadFile err: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("persisted = %q, want %q", got, payload)
	}

	recvEvent(t, ch, FileWrite)
}

var _ ftpserver.ClientContext = (*fakeClientContext)(nil)
