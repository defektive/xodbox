package xodbox

import (
	"net"
	"regexp"

	"github.com/defektive/xodbox/pkg/types"
	"github.com/defektive/xodbox/pkg/util"
)

// Config keys (under `defaults:`) for the global ignore/drop list. An event
// matching either rule is discarded before it is persisted or dispatched to
// notifiers — no DB row, no notification, no log line. Use this to silence a
// known-noisy source (e.g. a leftover beacon from an old test that keeps
// calling back every second) without muting the rest of your traffic.
const (
	// IgnoreCIDRsKey is a comma-separated list of source IPs/CIDRs to drop.
	IgnoreCIDRsKey = "ignore_cidrs"
	// IgnorePatternKey is a regex matched against the event FilterString
	// ("HANDLER ACTION DETAIL from IP[,IP...]"), so it can select on handler,
	// method, path, or source IP — e.g. "^HTTPX GET /old-test-callback".
	IgnorePatternKey = "ignore_pattern"
)

// ignoreRule decides whether an inbound event should be dropped entirely.
// A nil *ignoreRule matches nothing, so callers can hold one unconditionally.
type ignoreRule struct {
	cidrs   []*net.IPNet
	pattern *regexp.Regexp
}

// newIgnoreRule builds an ignoreRule from the app defaults map. It returns a
// non-nil rule even when nothing is configured (Matches then always reports
// false). A malformed CIDR list or regex is returned as an error so the
// operator sees the misconfiguration at startup instead of silently dropping
// or keeping everything.
func newIgnoreRule(defaults map[string]string) (*ignoreRule, error) {
	r := &ignoreRule{}

	cidrs, err := util.ParseCIDRs(defaults[IgnoreCIDRsKey])
	if err != nil {
		return nil, err
	}
	r.cidrs = cidrs

	if pat := defaults[IgnorePatternKey]; pat != "" {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, err
		}
		r.pattern = re
	}

	return r, nil
}

// active reports whether any rule is configured. Used to skip logging setup
// when the ignore list is empty (the common case).
func (r *ignoreRule) active() bool {
	return r != nil && (len(r.cidrs) > 0 || r.pattern != nil)
}

// Matches reports whether e should be dropped. Source IP is checked against
// the CIDR list; the FilterString is checked against the pattern. Either hit
// drops the event.
func (r *ignoreRule) Matches(e types.InteractionEvent) bool {
	if r == nil || e == nil {
		return false
	}
	if len(r.cidrs) > 0 && util.IPInAny(e.RemoteIP(), r.cidrs) {
		return true
	}
	if r.pattern != nil && r.pattern.MatchString(e.FilterString()) {
		return true
	}
	return false
}
