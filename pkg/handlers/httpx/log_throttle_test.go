package httpx

import (
	"testing"
	"time"
)

func TestLogThrottleAllowsOncePerInterval(t *testing.T) {
	tr := newLogThrottle(time.Minute)

	if !tr.allow("1.2.3.4") {
		t.Fatal("first call for a key should be allowed")
	}
	if tr.allow("1.2.3.4") {
		t.Error("second call within the interval should be throttled")
	}
	// A different key is independent.
	if !tr.allow("5.6.7.8") {
		t.Error("first call for a distinct key should be allowed")
	}
}

func TestLogThrottleAllowsAgainAfterInterval(t *testing.T) {
	tr := newLogThrottle(10 * time.Millisecond)

	if !tr.allow("1.2.3.4") {
		t.Fatal("first call should be allowed")
	}
	time.Sleep(15 * time.Millisecond)
	if !tr.allow("1.2.3.4") {
		t.Error("call after the interval elapsed should be allowed again")
	}
}

func TestLogThrottlePrunesStaleKeys(t *testing.T) {
	tr := newLogThrottle(5 * time.Millisecond)

	// Fill past the prune threshold with keys that will go stale.
	for i := 0; i < throttleMaxKeys+10; i++ {
		tr.allow(string(rune(i)) + "-a")
	}
	time.Sleep(10 * time.Millisecond)

	// This insert crosses the threshold and should trigger a prune of the now
	// stale entries above.
	tr.allow("trigger-prune")

	tr.mu.Lock()
	size := len(tr.last)
	tr.mu.Unlock()
	if size > throttleMaxKeys {
		t.Errorf("map not pruned: size %d > cap %d", size, throttleMaxKeys)
	}
}
