package xodbox

import (
	"os"
	"path/filepath"
	"testing"

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
