package xodbox

import (
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/types"
)

type recordingNotifier struct {
	mu     sync.Mutex
	events []types.InteractionEvent
	hits   int32
}

func (r *recordingNotifier) Name() string           { return "recorder" }
func (r *recordingNotifier) Filter() *regexp.Regexp { return regexp.MustCompile(".*") }
func (r *recordingNotifier) Send(e types.InteractionEvent) error {
	atomic.AddInt32(&r.hits, 1)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func TestRunForwardsEventsToAllNotifiers(t *testing.T) {
	n1 := &recordingNotifier{}
	n2 := &recordingNotifier{}

	cfg := &Config{
		Notifiers: []types.Notifier{n1, n2},
		Handlers:  []types.Handler{}, // no handlers — Run goes straight to waitForEvents
	}
	app := NewApp(cfg)

	go app.Run()

	// Wait briefly until the consumer goroutine is ready, then send an event.
	evt := &types.BaseEvent{RemoteAddr: "10.0.0.1"}
	app.eventChan <- evt

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&n1.hits) >= 1 && atomic.LoadInt32(&n2.hits) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if got := atomic.LoadInt32(&n1.hits); got != 1 {
		t.Errorf("n1 hits = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&n2.hits); got != 1 {
		t.Errorf("n2 hits = %d, want 1", got)
	}
}

func TestEmbeddedConfigAvailable(t *testing.T) {
	// Sanity check: the embedded config FS is reachable via its helpers.
	entries, err := ReadDir("config")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("embedded config dir should contain entries")
	}

	if _, err := EmbeddedConfigReadFile("config/" + ConfigFileName); err != nil {
		t.Errorf("EmbeddedConfigReadFile %s: %v", ConfigFileName, err)
	}

	f, err := Open("config/" + ConfigFileName)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
}
