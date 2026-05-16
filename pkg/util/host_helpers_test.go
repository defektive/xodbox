package util

import (
	"net/http"
	"testing"
)

func TestGetHostAndPortFromRemoteAddr(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHost string
		wantPort int
	}{
		{"ipv4 with port", "1.2.3.4:5678", "1.2.3.4", 5678},
		{"ipv4 no port", "1.2.3.4", "1.2.3.4", 0},
		{"ipv4 empty port", "1.2.3.4:", "1.2.3.4", 0},
		{"localhost", "127.0.0.1:8080", "127.0.0.1", 8080},
		{"ipv6 bracketed", "[::1]:9000", "::1", 9000},
		{"empty", "", "", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, port := GetHostAndPortFromRemoteAddr(tc.input)
			if host != tc.wantHost {
				t.Errorf("host: got %q, want %q", host, tc.wantHost)
			}
			if port != tc.wantPort {
				t.Errorf("port: got %d, want %d", port, tc.wantPort)
			}
		})
	}
}

func TestGetRemoteAddrFromRequest(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		realIP     string
		want       string
	}{
		{"no header passes through", "1.2.3.4:5678", "", "1.2.3.4:5678"},
		{"X-Real-Ip overrides host, keeps port", "1.2.3.4:5678", "9.10.11.12", "9.10.11.12:5678"},
		{"empty X-Real-Ip ignored", "1.2.3.4:5678", "", "1.2.3.4:5678"},
		{"no port preserved", "1.2.3.4", "", "1.2.3.4"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.RemoteAddr = tc.remoteAddr
			if tc.realIP != "" {
				req.Header.Set("X-Real-Ip", tc.realIP)
			}

			got := GetRemoteAddrFromRequest(req)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGetHostAndPortFromRequest(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.RemoteAddr = "1.2.3.4:5678"
	req.Header.Set("X-Real-Ip", "9.10.11.12")

	host, port := GetHostAndPortFromRequest(req)
	if host != "9.10.11.12" {
		t.Errorf("host: got %q, want %q", host, "9.10.11.12")
	}
	if port != 5678 {
		t.Errorf("port: got %d, want %d", port, 5678)
	}
}
