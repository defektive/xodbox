package util

import "testing"

func TestParseCIDRs(t *testing.T) {
	nets, err := ParseCIDRs(" 10.0.0.0/8 , 203.0.113.7 , ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("parsed %d nets, want 2 (empty entries skipped)", len(nets))
	}

	if _, err := ParseCIDRs(""); err != nil {
		t.Errorf("empty spec should not error: %v", err)
	}

	if _, err := ParseCIDRs("nonsense"); err == nil {
		t.Error("invalid entry should error")
	}
}

func TestIPInAny(t *testing.T) {
	nets, err := ParseCIDRs("10.0.0.0/8,203.0.113.7,2001:db8::/32")
	if err != nil {
		t.Fatalf("ParseCIDRs: %v", err)
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"203.0.113.7", true},
		{"203.0.113.8", false},
		{"2001:db8::1", true},
		{"2001:dead::1", false},
		{"8.8.8.8", false},
		{"not-an-ip", false},
	}
	for _, c := range cases {
		if got := IPInAny(c.ip, nets); got != c.want {
			t.Errorf("IPInAny(%q) = %v, want %v", c.ip, got, c.want)
		}
	}

	if IPInAny("10.0.0.1", nil) {
		t.Error("empty net list should never match")
	}
}
