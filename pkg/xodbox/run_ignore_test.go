package xodbox

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
)

// TestAppDropsIgnoredEvents verifies that an event whose source matches the
// configured ignore list is neither persisted nor sent to notifiers, while a
// non-matching event flowing right behind it is processed normally.
func TestAppDropsIgnoredEvents(t *testing.T) {
	const ignoredIP = "203.0.113.200"
	const keptIP = "203.0.113.201"

	n := &recordingNotifier{}
	app := NewApp(&Config{
		TemplateData: map[string]string{IgnoreCIDRsKey: ignoredIP},
		Notifiers:    []types.Notifier{n},
		Handlers:     []types.Handler{},
	})
	go app.Run()

	ignoredFilter := model.InteractionFilter{Handler: "tcp", RemoteAddr: ignoredIP}
	before := model.CountInteractions(ignoredFilter)

	app.eventChan <- &persistableEvent{
		BaseEvent: &types.BaseEvent{RemoteAddr: ignoredIP},
		rec:       &model.Interaction{Handler: "tcp", RemoteAddr: ignoredIP},
	}
	// A kept event behind the ignored one; once its notifier fires we know the
	// loop has moved past the ignored event.
	app.eventChan <- &persistableEvent{
		BaseEvent: &types.BaseEvent{RemoteAddr: keptIP},
		rec:       &model.Interaction{Handler: "tcp", RemoteAddr: keptIP},
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&n.hits) < 1 {
		time.Sleep(10 * time.Millisecond)
	}

	// The kept event should have reached the notifier exactly once; the ignored
	// event must not have.
	if got := atomic.LoadInt32(&n.hits); got != 1 {
		t.Fatalf("notifier hits = %d, want 1 (only the kept event)", got)
	}
	n.mu.Lock()
	for _, e := range n.events {
		if e.RemoteIP() == ignoredIP {
			t.Errorf("notifier received ignored event from %s", ignoredIP)
		}
	}
	n.mu.Unlock()

	// Give the persister time, then confirm the ignored event was not stored.
	time.Sleep(150 * time.Millisecond)
	if got := model.CountInteractions(ignoredFilter); got != before {
		t.Errorf("ignored event was persisted: count %d -> %d", before, got)
	}
}
