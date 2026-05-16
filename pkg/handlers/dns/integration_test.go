package dns

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
	"github.com/miekg/dns"
)

// freeUDPPort grabs a UDP port on loopback by binding then closing.
// Racy in principle, fine in practice for a single integration test.
func freeUDPPort(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	addr := c.LocalAddr().String()
	if err := c.Close(); err != nil {
		t.Fatalf("close udp reservation: %v", err)
	}
	return addr
}

func TestHandlerStartServesAQuery(t *testing.T) {
	addr := freeUDPPort(t)

	h := NewHandler(map[string]string{
		"listener":   addr,
		"default_ip": "192.0.2.42",
	}).(*Handler)

	eventChan := make(chan types.InteractionEvent, 8)
	go func() {
		_ = h.Start(nil, eventChan)
	}()

	client := &dns.Client{Timeout: 500 * time.Millisecond}
	msg := new(dns.Msg)
	msg.SetQuestion("test.example.", dns.TypeA)

	var resp *dns.Msg
	var err error
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, _, err = client.Exchange(msg, addr)
		if err == nil && resp != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dns query: %v", err)
	}
	if resp == nil || len(resp.Answer) == 0 {
		t.Fatal("no answers in response")
	}

	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected *dns.A, got %T", resp.Answer[0])
	}
	if a.A.String() != "192.0.2.42" {
		t.Errorf("response A = %s, want 192.0.2.42", a.A.String())
	}

	select {
	case evt := <-eventChan:
		details := evt.Details()
		if !strings.Contains(details, "test.example.") {
			t.Errorf("event details = %q, want to include test.example.", details)
		}
	case <-time.After(time.Second):
		t.Fatal("no event dispatched within 1s")
	}
}
