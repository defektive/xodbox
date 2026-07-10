package xodbox

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
)

// TestMain points the model DB singleton at one stable temp database for the
// whole package so persistInteraction has somewhere to write without creating a
// stray xodbox.db in the source tree.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "xodbox-run-test-*")
	if err != nil {
		panic(err)
	}
	model.LoadDBWithOptions(model.DBOptions{Path: filepath.Join(dir, "test.db")})
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// persistableEvent is a minimal event that carries a prebuilt Interaction.
type persistableEvent struct {
	*types.BaseEvent
	rec *model.Interaction
}

func (p *persistableEvent) Interaction() *model.Interaction { return p.rec }

// suppressedEvent is persistable but opts out of notifier delivery (like an
// httpx suspected-bot event).
type suppressedEvent struct {
	*types.BaseEvent
	rec *model.Interaction
}

func (s *suppressedEvent) Interaction() *model.Interaction { return s.rec }
func (s *suppressedEvent) NotifySuppressed() bool          { return true }

// TestSuppressedEventPersistsButSkipsNotifiers verifies the regression fix: an
// event flagged as notify-suppressed (e.g. a bot) is still persisted, but no
// notifier is invoked for it.
func TestSuppressedEventPersistsButSkipsNotifiers(t *testing.T) {
	n := &recordingNotifier{}
	app := NewApp(&Config{Notifiers: []types.Notifier{n}, Handlers: []types.Handler{}})
	go app.Run()

	f := model.InteractionFilter{Handler: "tcp", RemoteAddr: "203.0.113.55"}
	before := model.CountInteractions(f)

	app.eventChan <- &suppressedEvent{
		BaseEvent: &types.BaseEvent{RemoteAddr: "203.0.113.55"},
		rec: &model.Interaction{
			Handler: "tcp", Protocol: "tcp", RequestType: "Connection",
			RemoteAddr: "203.0.113.55",
		},
	}

	// Wait until the event loop has persisted it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && model.CountInteractions(f) < before+1 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := model.CountInteractions(f); got != before+1 {
		t.Fatalf("suppressed event not persisted: count %d, want %d", got, before+1)
	}

	// Give any (erroneous) notifier dispatch time to land; it must not have.
	time.Sleep(150 * time.Millisecond)
	if got := atomic.LoadInt32(&n.hits); got != 0 {
		t.Errorf("notifier fired %d times for a suppressed event, want 0", got)
	}
}

func TestPersistInteractionStoresPersistableEvents(t *testing.T) {
	f := model.InteractionFilter{Handler: "tcp", RemoteAddr: "203.0.113.7"}
	before := model.CountInteractions(f)

	persistInteraction(&persistableEvent{
		BaseEvent: &types.BaseEvent{RemoteAddr: "203.0.113.7"},
		rec: &model.Interaction{
			Handler:     "tcp",
			Protocol:    "tcp",
			RequestType: "Connection",
			RemoteAddr:  "203.0.113.7",
		},
	})

	if got := model.CountInteractions(f); got != before+1 {
		t.Fatalf("persistable event: count = %d, want %d", got, before+1)
	}
}

func TestPersistInteractionIgnoresNonPersistableAndNil(t *testing.T) {
	all := model.InteractionFilter{}
	before := model.CountInteractions(all)

	// A plain BaseEvent does not implement Persistable — no row.
	persistInteraction(&types.BaseEvent{RemoteAddr: "203.0.113.8"})
	// A Persistable event may still opt out by returning nil — no row.
	persistInteraction(&persistableEvent{BaseEvent: &types.BaseEvent{}, rec: nil})

	if got := model.CountInteractions(all); got != before {
		t.Fatalf("non-persistable/nil events changed count: %d -> %d", before, got)
	}
}
