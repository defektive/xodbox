package httpx

import (
	"sync"
	"time"
)

// throttleMaxKeys bounds the per-key timestamp map so a scanner cycling through
// many source IPs can't grow it without limit. When exceeded, stale entries
// (older than the throttle interval) are pruned opportunistically.
const throttleMaxKeys = 1024

// logThrottle rate-limits repetitive log lines per key (e.g. per source IP), so
// a high-volume source doesn't emit one line per request even at debug level.
type logThrottle struct {
	mu       sync.Mutex
	last     map[string]time.Time
	interval time.Duration
}

func newLogThrottle(interval time.Duration) *logThrottle {
	return &logThrottle{last: map[string]time.Time{}, interval: interval}
}

// allow reports whether a message for key may be emitted now. It returns true
// at most once per interval per key, recording the emit time when it does.
func (t *logThrottle) allow(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	if prev, ok := t.last[key]; ok && now.Sub(prev) < t.interval {
		return false
	}

	// Prune stale entries before inserting a new key once the map grows large,
	// so distinct-IP floods don't leak memory.
	if len(t.last) > throttleMaxKeys {
		for k, ts := range t.last {
			if now.Sub(ts) >= t.interval {
				delete(t.last, k)
			}
		}
		// If all entries are still fresh after pruning (e.g. a flood of unique
		// IPs all within the current interval), reset the map to keep memory
		// bounded. Affected keys will be re-logged on next call, but that is
		// preferable to unbounded growth.
		if len(t.last) > throttleMaxKeys {
			t.last = make(map[string]time.Time)
		}
	}

	t.last[key] = now
	return true
}

// botSuppressLog throttles the suspected-bot suppression line to at most once
// per source per minute.
var botSuppressLog = newLogThrottle(time.Minute)
