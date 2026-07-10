package httpx

import (
	"io/fs"
	"net"
	"net/http"
	"strings"
)

// uiBasePlaceholder is substituted in index.html with the configured mount
// path so the same compiled bundle works under any ui_path.
const uiBasePlaceholder = "{{XODBOX_BASE}}"

// newUIHandler serves the embedded admin SPA. mountPath is the normalized
// path prefix the UI is mounted at (e.g. "/admin/"); requests reaching this
// handler have already had that prefix stripped. Unknown non-asset paths fall
// back to index.html for client-side routing.
func newUIHandler(mountPath string) (http.Handler, error) {
	sub, err := fs.Sub(embeddedUIFS, "webui")
	if err != nil {
		return nil, err
	}
	raw, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return nil, err
	}
	indexHTML := []byte(strings.ReplaceAll(string(raw), uiBasePlaceholder, mountPath))
	fileServer := http.FileServer(http.FS(sub))

	serveIndex := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(indexHTML)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uiSecurityHeaders(w)

		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean == "" || clean == "index.html" {
			serveIndex(w)
			return
		}
		// Serve a real asset if it exists; otherwise SPA fallback.
		if f, ferr := sub.Open(clean); ferr == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		serveIndex(w)
	}), nil
}

// uiSecurityHeaders applies a strict, self-contained security posture to the
// admin UI. The SPA loads only its own bundled assets, so a tight CSP with no
// external origins is safe and blocks injected content.
func uiSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; connect-src 'self'; font-src 'self' data:; "+
			"frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
}

// cidrAllowlist restricts a handler to source IPs within the configured CIDRs.
// The check uses the real TCP peer (r.RemoteAddr), never a client-supplied
// forwarding header, so it can't be spoofed. Denied requests get a 404 so the
// admin surface is indistinguishable from an unconfigured path. With no CIDRs
// configured the allowlist is a no-op (auth still applies in later phases).
func cidrAllowlist(nets []*net.IPNet, next http.Handler) http.Handler {
	if len(nets) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ipAllowed(nets, r.RemoteAddr) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func ipAllowed(nets []*net.IPNet, remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseCIDRs parses a comma-separated list of CIDR blocks (bare IPs are
// accepted and treated as /32 or /128). Invalid entries are skipped and the
// list of successfully parsed networks is returned along with any bad entries.
func parseCIDRs(csv string) ([]*net.IPNet, []string) {
	var nets []*net.IPNet
	var bad []string
	for _, part := range strings.Split(csv, ",") {
		orig := strings.TrimSpace(part)
		if orig == "" {
			continue
		}
		cidr := orig
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			bad = append(bad, orig)
			continue
		}
		nets = append(nets, n)
	}
	return nets, bad
}
