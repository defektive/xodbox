package util

import (
	"fmt"
	"net/url"
	"strconv"
)

func HostAndPortFromRemoteAddr(remoteAddr string) (string, int) {

	remoteAddrURL := fmt.Sprintf("https://%s", remoteAddr)
	parsedURL, _ := url.Parse(remoteAddrURL)
	portNum, _ := strconv.Atoi(parsedURL.Port())

	return parsedURL.Hostname(), portNum
}
