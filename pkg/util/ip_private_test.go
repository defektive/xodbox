package util

import "testing"

func TestIsPrivateOrLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":      true,  // loopback
		"::1":            true,  // loopback v6
		"10.0.0.5":       true,  // RFC1918
		"192.168.1.10":   true,  // RFC1918
		"172.16.0.1":     true,  // RFC1918
		"169.254.10.1":   true,  // link-local
		"203.0.113.9":    false, // public
		"8.8.8.8":        false, // public
		"":               false, // not an IP
		"example.com":    false, // hostname
		"not-an-ip:1234": false, // includes port / not bare IP
	}
	for host, want := range cases {
		if got := IsPrivateOrLoopback(host); got != want {
			t.Errorf("IsPrivateOrLoopback(%q) = %v, want %v", host, got, want)
		}
	}
}
