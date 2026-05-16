package httpx

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewHandlerNameAndDefaults(t *testing.T) {
	h := NewHandler(map[string]string{
		"listener": "127.0.0.1:8080",
	})

	if h.Name() != "HTTPX" {
		t.Errorf("Name() = %q, want HTTPX", h.Name())
	}

	c, ok := h.(*Handler)
	if !ok {
		t.Fatalf("NewHandler returned %T, want *Handler", h)
	}
	if c.Listener != "127.0.0.1:8080" {
		t.Errorf("Listener = %q, want 127.0.0.1:8080", c.Listener)
	}
	if c.AutoCert {
		t.Error("AutoCert should default to false when tls_names is unset")
	}
	if len(c.TLSNames) != 0 {
		t.Errorf("TLSNames = %v, want empty", c.TLSNames)
	}
}

func TestNewHandlerWiresOptions(t *testing.T) {
	h := NewHandler(map[string]string{
		"listener":              "0.0.0.0:80",
		"tls_names":             "a.example,b.example",
		"dns_provider":          "route53",
		"dns_provider_api_user": "u",
		"dns_provider_api_key":  "k",
		"acme_email":            "e@x.example",
		"acme_accept":           "true",
		"acme_url":              "https://acme.example/dir",
		"mdaas_log_level":       "debug",
		"mdaas_bind_listener":   ":4444",
		"mdaas_allowed_cidr":    "10.0.0.0/8",
		"mdaas_notify_url":      "https://hook.example",
		"api_path":              "/x/api",
		"api_token":             "tok",
		"static_dir":            "/tmp/xodbox-static-test",
	}).(*Handler)

	if !h.AutoCert {
		t.Error("AutoCert should be true when tls_names is set")
	}
	if got := h.TLSNames; len(got) != 2 || got[0] != "a.example" || got[1] != "b.example" {
		t.Errorf("TLSNames = %v, want [a.example b.example]", got)
	}
	if h.DNSProvider != "route53" {
		t.Errorf("DNSProvider = %q, want route53", h.DNSProvider)
	}
	if h.ACMEEmail != "e@x.example" {
		t.Errorf("ACMEEmail = %q, want e@x.example", h.ACMEEmail)
	}
	if !h.ACMEAccept {
		t.Error("ACMEAccept should be true when acme_accept=\"true\"")
	}
	if h.MDaaSAllowedCIDR != "10.0.0.0/8" {
		t.Errorf("MDaaSAllowedCIDR = %q", h.MDaaSAllowedCIDR)
	}
	if h.APIPath != "/x/api" {
		t.Errorf("APIPath = %q, want /x/api", h.APIPath)
	}
	if h.APIToken != "tok" {
		t.Errorf("APIToken = %q, want tok", h.APIToken)
	}
	if h.StaticDir != "/tmp/xodbox-static-test" {
		t.Errorf("StaticDir = %q", h.StaticDir)
	}
}

func TestNewHandlerACMEAcceptFalseByDefault(t *testing.T) {
	h := NewHandler(map[string]string{"acme_accept": "yes"}).(*Handler)
	if h.ACMEAccept {
		t.Error("ACMEAccept should only be true for exact value \"true\"")
	}
}

func TestHostOnly(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"127.0.0.1:443", "127.0.0.1"},
		{"[::1]:80", "::1"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := hostOnly(tc.input); got != tc.want {
				t.Errorf("hostOnly(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestHttpRedirectHandlerRedirectsToHTTPS(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com:8080/path?q=1", nil)
	req.Host = "example.com:8080"

	httpRedirectHandler(rr, req)

	if rr.Code != http.StatusMovedPermanently {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMovedPermanently)
	}
	if got := rr.Header().Get("Location"); got != "https://example.com/path?q=1" {
		t.Errorf("Location = %q, want %q", got, "https://example.com/path?q=1")
	}
	if got := rr.Header().Get("Connection"); got != "close" {
		t.Errorf("Connection = %q, want close", got)
	}
}

func TestDebounceCoalescesCalls(t *testing.T) {
	var count int32
	deb := Debounce(50 * time.Millisecond)

	for i := 0; i < 5; i++ {
		deb(func() { atomic.AddInt32(&count, 1) })
		time.Sleep(10 * time.Millisecond)
	}

	// After all calls, only the last scheduled timer should fire.
	time.Sleep(150 * time.Millisecond)

	if got := atomic.LoadInt32(&count); got != 1 {
		t.Errorf("debounced call count = %d, want 1", got)
	}
}

func TestDebounceFiresMultipleTimesAfterQuiescence(t *testing.T) {
	var count int32
	deb := Debounce(30 * time.Millisecond)

	deb(func() { atomic.AddInt32(&count, 1) })
	time.Sleep(80 * time.Millisecond) // let it fire

	deb(func() { atomic.AddInt32(&count, 1) })
	time.Sleep(80 * time.Millisecond) // let it fire again

	if got := atomic.LoadInt32(&count); got != 2 {
		t.Errorf("debounced call count = %d, want 2", got)
	}
}

func TestDebouncerConcurrentAddsSafe(t *testing.T) {
	deb := Debounce(20 * time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			deb(func() {})
		}()
	}
	wg.Wait()
	// Race detector handles correctness; this test exists to exercise
	// concurrent paths under `go test -race`.
}
