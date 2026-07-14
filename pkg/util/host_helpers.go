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

// ParseCIDRs parses a comma-separated list of CIDRs and bare IPs into
// networks. A bare IP (e.g. "1.2.3.4" or "2001:db8::1") is treated as a
// single-host network (/32 or /128). Empty entries and surrounding
// whitespace are ignored; an empty spec yields a nil slice and no error.
// The first unparseable entry returns an error so config mistakes surface
// loudly rather than silently matching nothing.
func ParseCIDRs(spec string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, raw := range strings.Split(spec, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			if ip := net.ParseIP(entry); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				entry = fmt.Sprintf("%s/%d", entry, bits)
			}
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR/IP %q: %w", strings.TrimSpace(raw), err)
		}
		nets = append(nets, network)
	}
	return nets, nil
}

// IPInAny reports whether host (a bare IP, no port) falls within any of the
// given networks. A non-IP host or an empty network list returns false.
func IPInAny(host string, nets []*net.IPNet) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
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
