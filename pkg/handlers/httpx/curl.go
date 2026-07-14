package httpx

import (
	"bufio"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/defektive/xodbox/pkg/model"
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
	return buildCurl(r.Method, target, r.Header, e.body)
}

// CurlFromInteraction reconstructs a replay curl command from a persisted
// interaction (for the admin UI's copy-as-curl). The stored Headers field is
// the raw request dump (request line + headers, with the body appended); we
// parse the header section and pair it with the stored body.
func CurlFromInteraction(i *model.Interaction) string {
	raw := i.Headers
	if idx := strings.Index(raw, "\r\n\r\n"); idx >= 0 {
		raw = raw[:idx+4] // headers only; drop the appended body copy
	}
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		// Fall back to the structured columns when the dump can't be parsed.
		scheme := schemeFor(i.Protocol)
		return buildCurl(i.RequestType, scheme+"://"+i.RemoteAddr+i.RequestTarget, http.Header{}, i.Data)
	}
	target := schemeFor(i.Protocol) + "://" + req.Host + req.URL.RequestURI()
	return buildCurl(req.Method, target, req.Header, i.Data)
}

func schemeFor(protocol string) string {
	if protocol == "https" {
		return "https"
	}
	return "http"
}

// buildCurl renders a single-line, shell-safe curl command from the request
// parts. Content-Length is skipped (curl derives it); headers are emitted in a
// stable order for reproducibility.
func buildCurl(method, target string, header http.Header, body []byte) string {
	var b strings.Builder
	b.WriteString("curl")
	if method != "" && (method != http.MethodGet || len(body) > 0) {
		b.WriteString(" -X " + method)
	}
	b.WriteString(" " + shellSingleQuote(target))

	keys := make([]string, 0, len(header))
	for k := range header {
		if curlSkipHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range header[k] {
			b.WriteString(" -H " + shellSingleQuote(k+": "+v))
		}
	}

	const maxCurlBody = 4096
	if len(body) > 0 {
		if !utf8.Valid(body) {
			b.WriteString(" # binary body omitted — download via the Files tab")
		} else if len(body) > maxCurlBody {
			b.WriteString(" --data-raw " + shellSingleQuote(string(body[:maxCurlBody])))
			b.WriteString(" # body truncated")
		} else {
			b.WriteString(" --data-raw " + shellSingleQuote(string(body)))
		}
	}
	return b.String()
}
