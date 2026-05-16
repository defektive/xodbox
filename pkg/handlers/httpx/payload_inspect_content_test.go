package httpx

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"image/gif"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func reqWithBody(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, url, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	r.RemoteAddr = "127.0.0.1:54321"
	return r
}

func TestInspectHTML(t *testing.T) {
	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/page.html", ""))
	rr := httptest.NewRecorder()
	if err := Inspect(rr, e); err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html...", ct)
	}
	if !strings.Contains(rr.Body.String(), "<h1>HTML Request</h1>") {
		t.Errorf("HTML body missing header: %q", rr.Body.String())
	}
}

func TestInspectJSON(t *testing.T) {
	e := NewEvent(reqWithBody(t, http.MethodPost, "http://x/data.json", `payload`))
	rr := httptest.NewRecorder()
	if err := Inspect(rr, e); err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json...", ct)
	}

	var rs RequestStruct
	if err := json.Unmarshal(rr.Body.Bytes(), &rs); err != nil {
		t.Fatalf("JSON unmarshal: %v\nbody: %s", err, rr.Body.String())
	}
	if rs.Method != http.MethodPost {
		t.Errorf("Method = %q, want POST", rs.Method)
	}
	if rs.Path != "/data.json" {
		t.Errorf("Path = %q, want /data.json", rs.Path)
	}
	if rs.Body != "payload" {
		t.Errorf("Body = %q, want payload", rs.Body)
	}
}

func TestInspectJSONArrayWrap(t *testing.T) {
	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/d.json?array", ""))
	rr := httptest.NewRecorder()
	if err := Inspect(rr, e); err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	body := rr.Body.String()
	if !strings.HasPrefix(body, "[") || !strings.HasSuffix(body, "]") {
		t.Errorf("array mode should wrap output in [...], got %q", body)
	}
}

func TestInspectXML(t *testing.T) {
	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/d.xml", "xb"))
	rr := httptest.NewRecorder()
	if err := Inspect(rr, e); err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/xml") {
		t.Errorf("Content-Type = %q, want text/xml...", ct)
	}

	// MarshalXML is hand-rolled and the standard library cannot
	// round-trip the headers map, so check the output contains the
	// hand-rolled elements directly.
	body := rr.Body.String()
	for _, want := range []string{
		"<method>GET</method>",
		"<path>/d.xml</path>",
		"<headers>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("XML body missing %q, got %q", want, body)
		}
	}

	// Verify the encoded document is at least well-formed XML.
	dec := xml.NewDecoder(strings.NewReader(body))
	for {
		_, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("XML not well-formed: %v", err)
		}
	}
}

func TestInspectJS(t *testing.T) {
	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/p.js", ""))
	rr := httptest.NewRecorder()
	if err := Inspect(rr, e); err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !strings.HasPrefix(rr.Body.String(), "let reqResponse = ") {
		t.Errorf("JS body should start with var assignment, got %q", rr.Body.String())
	}
}

func TestInspectPNG(t *testing.T) {
	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/img.png", ""))
	rr := httptest.NewRecorder()
	if err := Inspect(rr, e); err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	if rr.Header().Get("Content-Type") != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", rr.Header().Get("Content-Type"))
	}
	if _, err := png.Decode(rr.Body); err != nil {
		t.Errorf("response body should be a decodable PNG: %v", err)
	}
}

func TestInspectJPG(t *testing.T) {
	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/img.jpg", ""))
	rr := httptest.NewRecorder()
	if err := Inspect(rr, e); err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if rr.Header().Get("Content-Type") != "image/jpeg" {
		t.Errorf("Content-Type = %q, want image/jpeg", rr.Header().Get("Content-Type"))
	}
	if _, err := jpeg.Decode(rr.Body); err != nil {
		t.Errorf("response body should be a decodable JPEG: %v", err)
	}
}

func TestInspectGIF(t *testing.T) {
	e := NewEvent(reqWithBody(t, http.MethodGet, "http://x/img.gif", ""))
	rr := httptest.NewRecorder()
	if err := Inspect(rr, e); err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if rr.Header().Get("Content-Type") != "image/gif" {
		t.Errorf("Content-Type = %q, want image/gif", rr.Header().Get("Content-Type"))
	}
	if _, err := gif.Decode(rr.Body); err != nil {
		t.Errorf("response body should be a decodable GIF: %v", err)
	}
}
