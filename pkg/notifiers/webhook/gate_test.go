package webhook

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/defektive/xodbox/pkg/types"
)

// filterEvent is a minimal InteractionEvent whose FilterString is fixed and
// whose Data differs, proving the notifier gates on FilterString.
type filterEvent struct {
	*types.BaseEvent
	fs string
}

func (e filterEvent) FilterString() string { return e.fs }

func TestSendGatesOnFilterString(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, "^SMB Auth")

	// Data() says "SMB Auth ..." but FilterString() says DNS — must NOT send,
	// proving the gate uses FilterString, not Data.
	nonMatch := filterEvent{
		BaseEvent: &types.BaseEvent{RawData: []byte("SMB Auth CORP\\alice")},
		fs:        "DNS A evil.com from 1.2.3.4",
	}
	if err := n.Send(nonMatch); err != nil {
		t.Fatalf("Send(nonMatch) = %v", err)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("non-matching event was sent (hits=%d)", hits)
	}

	match := filterEvent{
		BaseEvent: &types.BaseEvent{},
		fs:        "SMB Auth CORP\\alice from 10.0.0.5",
	}
	if err := n.Send(match); err != nil {
		t.Fatalf("Send(match) = %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("matching event not sent (hits=%d)", hits)
	}
}
