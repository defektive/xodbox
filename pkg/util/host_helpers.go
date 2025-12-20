package util

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

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
