package util

import (
	"net/http"
	"strings"
	"testing"
)

func TestRequestIPChain(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		realIP     string
		want       string
	}{
		{
			name:       "peer only",
			remoteAddr: "10.0.0.5:44321",
			want:       "10.0.0.5",
		},
		{
			name:       "x-forwarded-for chain then peer",
			remoteAddr: "10.0.0.1:5000",
			xff:        "203.0.113.9, 198.51.100.2",
			want:       "203.0.113.9,198.51.100.2,10.0.0.1",
		},
		{
			name:       "dedup peer already in chain",
			remoteAddr: "203.0.113.9:5000",
			xff:        "203.0.113.9, 198.51.100.2",
			want:       "203.0.113.9,198.51.100.2",
		},
		{
			name:       "x-real-ip included and deduped",
			remoteAddr: "10.0.0.1:5000",
			xff:        "203.0.113.9",
			realIP:     "203.0.113.9",
			want:       "203.0.113.9,10.0.0.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{RemoteAddr: tc.remoteAddr, Header: http.Header{}}
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.realIP != "" {
				req.Header.Set("X-Real-Ip", tc.realIP)
			}
			if got := strings.Join(RequestIPChain(req), ","); got != tc.want {
				t.Errorf("RequestIPChain = %q, want %q", got, tc.want)
			}
		})
	}
}
