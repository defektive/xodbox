package httpx

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
)

func freeTCPAddr(t *testing.T) string {
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

func TestHandlerStartServesHTTP(t *testing.T) {
	addr := freeTCPAddr(t)
	h := NewHandler(map[string]string{
		"listener": addr,
	}).(*Handler)

	eventChan := make(chan types.InteractionEvent, 16)
	app := &stubApp{data: map[string]string{}}

	go func() {
		_ = h.Start(app, eventChan)
	}()

	// Wait until the server accepts connections.
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	if lastErr != nil && time.Now().After(deadline) {
		t.Fatalf("http listener never came up: %v", lastErr)
	}

	resp, err := http.Get("http://" + addr + "/probe")
	if err != nil {
		t.Fatalf("GET /probe: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	select {
	case evt := <-eventChan:
		if evt.RemoteIP() == "" {
			t.Error("dispatched event should have RemoteIP populated")
		}
	case <-time.After(time.Second):
		t.Fatal("no event dispatched within 1s")
	}
}
