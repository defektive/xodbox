package httpx

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "httpx-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	model.LoadDBWithOptions(model.DBOptions{Path: filepath.Join(dir, "test.db")})
	os.Exit(m.Run())
}

func newPOSTRequest(t *testing.T, url, body string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	r.RemoteAddr = "203.0.113.5:54321"
	r.Header.Set("User-Agent", "test-agent/1.0")
	return r
}

func TestEventBodyAndHeaders(t *testing.T) {
	r := newPOSTRequest(t, "http://example.com/path?q=1", "payload-body")
	e := NewEvent(r)

	if string(e.Body()) != "payload-body" {
		t.Errorf("Body() = %q, want %q", e.Body(), "payload-body")
	}

	headers := string(e.RequestHeaders())
	if !bytes.Contains([]byte(headers), []byte("POST /path?q=1 HTTP/1.1")) {
		t.Errorf("RequestHeaders() missing request line, got:\n%s", headers)
	}

	raw := string(e.RawRequest())
	if !bytes.Contains([]byte(raw), []byte("payload-body")) {
		t.Errorf("RawRequest() should include body, got:\n%s", raw)
	}
}

func TestEventRemoteAddrAndPort(t *testing.T) {
	r := newPOSTRequest(t, "http://example.com/", "")
	e := NewEvent(r)

	if e.RemoteAddr() != "203.0.113.5" {
		t.Errorf("RemoteAddr() = %q, want 203.0.113.5", e.RemoteAddr())
	}
	if e.RemotePortNumber != 54321 {
		t.Errorf("RemotePortNumber = %d, want 54321", e.RemotePortNumber)
	}
}

func TestEventRequestAccessor(t *testing.T) {
	r := newPOSTRequest(t, "http://example.com/x", "")
	e := NewEvent(r)
	if e.Request() != r {
		t.Error("Request() should return the wrapped *http.Request")
	}
}

func TestEventDetails(t *testing.T) {
	r := newPOSTRequest(t, "http://example.com/details", "")
	e := NewEvent(r)

	d := e.Details()
	for _, want := range []string{"HTTPX:", "POST", "/details", "203.0.113.5"} {
		if !bytes.Contains([]byte(d), []byte(want)) {
			t.Errorf("Details() = %q, want to contain %q", d, want)
		}
	}
}

func TestEventDispatchNonBot(t *testing.T) {
	r := newPOSTRequest(t, "http://example.com/", "")
	r.RemoteAddr = "198.51.100.42:33333"
	e := NewEvent(r)

	ch := make(chan types.InteractionEvent, 1)
	e.Dispatch(ch)

	select {
	case got := <-ch:
		if got != types.InteractionEvent(e) {
			t.Errorf("dispatched event differs from sender")
		}
	case <-time.After(time.Second):
		t.Fatal("Dispatch did not deliver event within 1s")
	}
}

func TestBotEventDispatchedButNotifySuppressed(t *testing.T) {
	// Public IP: not exempt, so volume-based bot detection still applies.
	const botIP = "203.0.113.99"

	// Seed >30 interactions for botIP so model.IsBot returns true.
	for i := 0; i < 31; i++ {
		model.DB().Create(&model.Interaction{RemoteAddr: botIP, Handler: "test"})
	}
	if !model.IsBot(botIP) {
		t.Fatalf("precondition: model.IsBot(%q) should be true after seeding", botIP)
	}

	r := newPOSTRequest(t, "http://example.com/", "")
	r.RemoteAddr = botIP + ":12345"
	e := NewEvent(r)

	// Dispatch now always delivers so the bot's traffic is still persisted; the
	// suppression applies only to notifiers, via NotifySuppressed().
	ch := make(chan types.InteractionEvent, 1)
	e.Dispatch(ch)
	select {
	case <-ch: // expected: still delivered (and persisted by the event loop)
	case <-time.After(time.Second):
		t.Fatal("Dispatch should still deliver a bot event so it is persisted")
	}
	if !e.NotifySuppressed() {
		t.Error("a suspected bot should be notify-suppressed")
	}
}

func TestPrivateExemptFromBotNotifySuppression(t *testing.T) {
	// A private IP that trips bot detection is exempt from notify-suppression
	// when bot_exempt_private is on (the default), and suppressed when off.
	const botIP = "10.0.0.77"
	for i := 0; i < 31; i++ {
		model.DB().Create(&model.Interaction{RemoteAddr: botIP, Handler: "test"})
	}
	if !model.IsBot(botIP) {
		t.Fatalf("precondition: model.IsBot(%q) should be true", botIP)
	}

	r := newPOSTRequest(t, "http://example.com/", "")
	r.RemoteAddr = botIP + ":12345"

	// Exempt (default): not suppressed despite bot volume.
	e := NewEvent(r) // botExemptPrivate defaults true
	if e.NotifySuppressed() {
		t.Error("private source should be exempt from bot detection (not notify-suppressed)")
	}

	// Exemption disabled: suppressed like any other bot.
	e2 := NewEvent(r)
	e2.botExemptPrivate = false
	if !e2.NotifySuppressed() {
		t.Error("with exemption off, a private bot should be notify-suppressed")
	}
}

func TestRawBodyFilename(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		cd        string // Content-Disposition header value (empty = omit)
		mediaType string
		want      string
	}{
		// Content-Disposition wins over path
		{
			name:      "content-disposition filename",
			path:      "/upload/ignored.bin",
			cd:        `attachment; filename="report.pdf"`,
			mediaType: "application/octet-stream",
			want:      "report.pdf",
		},
		// Content-Disposition with Windows path is sanitised
		{
			name:      "content-disposition windows path",
			path:      "/upload",
			cd:        `attachment; filename="C:\\Users\\alice\\notes.txt"`,
			mediaType: "text/plain",
			want:      "notes.txt",
		},
		// URL path segment
		{
			name:      "url path segment with extension",
			path:      "/uploads/photo.jpg",
			mediaType: "image/jpeg",
			want:      "photo.jpg",
		},
		{
			name:      "url path segment no extension",
			path:      "/webhook/callback",
			mediaType: "application/json",
			want:      "callback",
		},
		// Fallback to body.<ext>
		{
			name:      "root path falls back to extension",
			path:      "/",
			mediaType: "application/json",
			want:      "body.json",
		},
		{
			name:      "empty path falls back to extension",
			path:      "",
			mediaType: "application/pdf",
			want:      "body.pdf",
		},
		{
			name:      "unknown media type gets .bin",
			path:      "/",
			mediaType: "application/x-custom",
			want:      "body.bin",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodPut, "http://host"+tt.path, nil)
			if tt.cd != "" {
				r.Header.Set("Content-Disposition", tt.cd)
			}
			got := rawBodyFilename(r, tt.mediaType)
			if got != tt.want {
				t.Errorf("rawBodyFilename = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseRawBodyCreatesFile(t *testing.T) {
	body := []byte(`{"key":"value"}`)
	r, _ := http.NewRequest(http.MethodPost, "http://host/api/data", bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Content-Type", "application/json")
	e := NewEvent(r)

	parseRawBody(e, 0)

	if len(e.interaction.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(e.interaction.Files))
	}
	f := e.interaction.Files[0]
	if f.FileName != "data" {
		t.Errorf("FileName = %q, want %q", f.FileName, "data")
	}
	if f.ContentType != "application/json" {
		t.Errorf("ContentType = %q, want application/json", f.ContentType)
	}
	if f.Size != int64(len(body)) {
		t.Errorf("Size = %d, want %d", f.Size, len(body))
	}
}

func TestParseRawBodySkipsMultipart(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "http://host/upload",
		bytes.NewReader([]byte("--boundary\r\n")))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	e := NewEvent(r)
	parseRawBody(e, 0)
	if len(e.interaction.Files) != 0 {
		t.Errorf("parseRawBody should skip multipart, got %d files", len(e.interaction.Files))
	}
}

func TestParseRawBodySkipsEmpty(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "http://host/", bytes.NewReader(nil))
	r.RemoteAddr = "127.0.0.1:1234"
	e := NewEvent(r)
	parseRawBody(e, 0)
	if len(e.interaction.Files) != 0 {
		t.Errorf("parseRawBody should skip empty body, got %d files", len(e.interaction.Files))
	}
}

func TestEventTemplateContextHeadersAndQuery(t *testing.T) {
	r := newPOSTRequest(t, "http://example.com/p?a=1&a=2&b=x", "")
	r.Header.Set("X-Forwarded-For", "9.9.9.9")
	r.Header.Set("X-Real-IP", "8.8.8.8")
	e := NewEvent(r)

	td := map[string]string{
		"notify_string": "notify!",
		"server_name":   "test-srv",
	}
	tc := e.TemplateContext(td)

	if tc == nil {
		t.Fatal("TemplateContext returned nil")
	}
	if tc.NotifyString != "notify!" {
		t.Errorf("NotifyString = %q, want notify!", tc.NotifyString)
	}
	if tc.ServerName != "test-srv" {
		t.Errorf("ServerName = %q, want test-srv", tc.ServerName)
	}
	if tc.Request == nil {
		t.Fatal("Request context should not be nil")
	}
	if tc.Request.Host != "example.com" {
		t.Errorf("Host = %q, want example.com", tc.Request.Host)
	}
	if tc.Request.Path != "/p" {
		t.Errorf("Path = %q, want /p", tc.Request.Path)
	}

	wantRemotes := map[string]bool{
		"203.0.113.5:54321": true,
		"9.9.9.9":           true,
		"8.8.8.8":           true,
	}
	for _, r := range tc.Request.RemoteAddr {
		if !wantRemotes[r] {
			t.Errorf("unexpected remote %q", r)
		}
		delete(wantRemotes, r)
	}
	if len(wantRemotes) != 0 {
		t.Errorf("missing remotes: %v", wantRemotes)
	}

	// Multi-value query "a" should expand into GET_a_0, GET_a_1.
	if td["GET_a_0"] != "1" || td["GET_a_1"] != "2" {
		t.Errorf("multi-value query not expanded correctly: %v", td)
	}
	// Single-value query "b" should land under GET_b.
	if td["GET_b"] != "x" {
		t.Errorf("single-value query not set: %v", td)
	}
}
