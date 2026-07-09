package httpx

import (
	"net/http"
	"sort"
	"strings"
)

// curlSkipHeaders are request headers curl derives itself; reproducing them
// verbatim would conflict with the replayed request.
var curlSkipHeaders = map[string]bool{
	"Content-Length": true,
}

// shellSingleQuote wraps s in single quotes for safe use in a POSIX shell,
// escaping any embedded single quotes ('\” is the standard idiom).
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// CurlCommand renders a copy-pasteable curl command that reproduces the
// captured HTTP request: method, target URL, every header, and the body.
//
// This is aimed at SSRF workflows — when a vulnerable server is coerced
// into calling xodbox, the captured request often carries the headers,
// cookies, or cloud-metadata tokens the victim attached. Replaying it (and
// swapping the URL for the intended internal target) lets an operator
// inspect that target with the victim's own request.
func (e *Event) CurlCommand() string {
	r := e.req

	// Prefer an explicit URL scheme; otherwise infer from TLS. Server-side
	// requests usually carry no URL scheme, so TLS is the real signal.
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	target := scheme + "://" + host + r.URL.RequestURI()

	var b strings.Builder
	b.WriteString("curl")
	if r.Method != http.MethodGet || len(e.body) > 0 {
		b.WriteString(" -X " + r.Method)
	}
	b.WriteString(" " + shellSingleQuote(target))

	// Emit headers in a stable order so the command is reproducible.
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		if curlSkipHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range r.Header[k] {
			b.WriteString(" -H " + shellSingleQuote(k+": "+v))
		}
	}

	if len(e.body) > 0 {
		b.WriteString(" --data-raw " + shellSingleQuote(string(e.body)))
	}

	return b.String()
}
