package util

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// IsPrivateOrLoopback reports whether host is a loopback, RFC1918 private,
// or link-local IP address. host should be a bare IP (no port); non-IP
// hostnames return false. Used to exempt trusted/local sources (operators
// testing, internal SSRF callbacks) from volume-based bot detection.
func IsPrivateOrLoopback(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func GetRemoteAddrFromRequest(req *http.Request) string {

	ra := req.RemoteAddr
	ras := strings.Split(ra, ":")

	// nginx will overwrite
	if realIP := req.Header.Get("X-Real-Ip"); realIP != "" {
		ras[0] = realIP
	}

	// i don't trust this....
	//if forwardedFor := req.Header.Get("X-Forwarded-For"); forwardedFor != "" {
	//	fas := strings.Split(forwardedFor, ",")
	//	ras[0] = strings.TrimSpace(fas[len(fas)-1])
	//}
	return strings.Join(ras, ":")
}

func GetHostAndPortFromRequest(req *http.Request) (string, int) {

	return GetHostAndPortFromRemoteAddr(GetRemoteAddrFromRequest(req))
}

func GetHostAndPortFromRemoteAddr(remoteAddr string) (string, int) {

	remoteAddrURL := fmt.Sprintf("https://%s", remoteAddr)
	parsedURL, _ := url.Parse(remoteAddrURL)
	portNum, _ := strconv.Atoi(parsedURL.Port())

	return parsedURL.Hostname(), portNum
}

// RequestIPChain returns the unique, order-preserving chain of source IPs
// for an HTTP request: X-Forwarded-For entries (client first), then
// X-Real-Ip, then the direct TCP peer. Duplicates are collapsed. Forwarded
// headers are client-controlled and can be spoofed, so treat the chain as
// informational rather than authoritative.
func RequestIPChain(req *http.Request) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(ip string) {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			return
		}
		if _, ok := seen[ip]; ok {
			return
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}

	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		for _, p := range strings.Split(xff, ",") {
			add(p)
		}
	}
	add(req.Header.Get("X-Real-Ip"))
	if host, _ := GetHostAndPortFromRemoteAddr(req.RemoteAddr); host != "" {
		add(host)
	}
	return out
}
