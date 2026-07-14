package xodbox

import (
	"testing"

	"github.com/defektive/xodbox/pkg/types"
)

func TestNewIgnoreRuleEmptyIsInactive(t *testing.T) {
	r, err := newIgnoreRule(map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.active() {
		t.Error("empty defaults should produce an inactive rule")
	}
	if r.Matches(&types.BaseEvent{RemoteAddr: "1.2.3.4"}) {
		t.Error("inactive rule must not match anything")
	}
}

func TestIgnoreRuleCIDRMatch(t *testing.T) {
	r, err := newIgnoreRule(map[string]string{
		IgnoreCIDRsKey: "10.0.0.0/8, 203.0.113.7",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.active() {
		t.Fatal("rule with cidrs should be active")
	}

	cases := []struct {
		addr string
		want bool
	}{
		{"10.1.2.3", true},    // inside CIDR
		{"203.0.113.7", true}, // bare IP → /32
		{"203.0.113.8", false},
		{"8.8.8.8", false},
		{"not-an-ip", false},
	}
	for _, c := range cases {
		if got := r.Matches(&types.BaseEvent{RemoteAddr: c.addr}); got != c.want {
			t.Errorf("Matches(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestIgnoreRulePatternMatch(t *testing.T) {
	// BaseEvent.FilterString() is "<data> from <ip>", so drive the pattern off
	// the RawData payload.
	r, err := newIgnoreRule(map[string]string{
		IgnorePatternKey: "^beacon-callback",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.Matches(&types.BaseEvent{RawData: []byte("beacon-callback"), RemoteAddr: "8.8.8.8"}) {
		t.Error("event matching the pattern should be dropped")
	}
	if r.Matches(&types.BaseEvent{RawData: []byte("legit-traffic"), RemoteAddr: "8.8.8.8"}) {
		t.Error("event not matching the pattern should be kept")
	}
}

func TestIgnoreRuleInvalidConfig(t *testing.T) {
	if _, err := newIgnoreRule(map[string]string{IgnoreCIDRsKey: "not-a-cidr"}); err == nil {
		t.Error("invalid CIDR should return an error")
	}
	if _, err := newIgnoreRule(map[string]string{IgnorePatternKey: "("}); err == nil {
		t.Error("invalid regex should return an error")
	}
}

func TestIgnoreRuleNilSafe(t *testing.T) {
	var r *ignoreRule
	if r.active() {
		t.Error("nil rule should be inactive")
	}
	if r.Matches(&types.BaseEvent{RemoteAddr: "1.2.3.4"}) {
		t.Error("nil rule must not match")
	}
}
