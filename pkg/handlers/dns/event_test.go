package dns

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// fakeResponseWriter implements dns.ResponseWriter for unit tests.
type fakeResponseWriter struct {
	remote net.Addr
}

func (f *fakeResponseWriter) LocalAddr() net.Addr       { return nil }
func (f *fakeResponseWriter) RemoteAddr() net.Addr      { return f.remote }
func (f *fakeResponseWriter) WriteMsg(*dns.Msg) error   { return nil }
func (f *fakeResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (f *fakeResponseWriter) Close() error              { return nil }
func (f *fakeResponseWriter) TsigStatus() error         { return nil }
func (f *fakeResponseWriter) TsigTimersOnly(bool)       {}
func (f *fakeResponseWriter) Hijack()                   {}

func TestNewHandlerWiresConfig(t *testing.T) {
	h := NewHandler(map[string]string{
		"listener":   ":1053",
		"default_ip": "10.20.30.40",
	}).(*Handler)

	if h.Name() != "DNS" {
		t.Errorf("Name() = %q, want DNS", h.Name())
	}
	if h.Listener != ":1053" {
		t.Errorf("Listener = %q, want :1053", h.Listener)
	}
	if h.DefaultResponseIP != "10.20.30.40" {
		t.Errorf("DefaultResponseIP = %q, want 10.20.30.40", h.DefaultResponseIP)
	}
}

func TestNewEventCarriesRemoteAddrAndPort(t *testing.T) {
	w := &fakeResponseWriter{
		remote: &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 5353},
	}
	req := new(dns.Msg)
	req.SetQuestion("example.test.", dns.TypeA)

	e := newEvent(w, req).(*Event)
	if e.RemoteIP() != "198.51.100.7" {
		t.Errorf("RemoteIP = %q, want 198.51.100.7", e.RemoteIP())
	}
	if e.RemotePort() != 5353 {
		t.Errorf("RemotePort = %d, want 5353", e.RemotePort())
	}
	if e.UserAgent() != "unknown" {
		t.Errorf("UserAgent = %q, want unknown", e.UserAgent())
	}
	if !strings.Contains(e.Data(), "example.test.") {
		t.Errorf("Data should include question name, got %q", e.Data())
	}
}

func TestEventDetailsIncludesQuestion(t *testing.T) {
	w := &fakeResponseWriter{remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}}
	req := new(dns.Msg)
	req.SetQuestion("foo.bar.example.", dns.TypeAAAA)

	e := newEvent(w, req).(*Event)
	d := e.Details()

	if !strings.HasPrefix(d, "DNS: ") {
		t.Errorf("Details should start with 'DNS: ', got %q", d)
	}
	if !strings.Contains(d, "foo.bar.example.") {
		t.Errorf("Details should contain question name, got %q", d)
	}
}

func TestEventDetailsNoQuestion(t *testing.T) {
	w := &fakeResponseWriter{remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}}
	req := new(dns.Msg) // no questions

	e := newEvent(w, req).(*Event)
	if e.Details() != "DNS: " {
		t.Errorf("Details with no questions = %q, want %q", e.Details(), "DNS: ")
	}
}
