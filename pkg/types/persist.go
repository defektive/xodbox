package types

import "github.com/defektive/xodbox/pkg/model"

// Persistable is implemented by interaction events that can be stored as a
// model.Interaction. The application's event loop persists every event that
// implements this interface (see pkg/xodbox), so a handler only has to build
// the record — it never touches the database directly. Returning nil skips
// persistence for that particular event.
type Persistable interface {
	Interaction() *model.Interaction
}

// NotifySuppressor is implemented by events that should still be persisted but
// skip notifier delivery. httpx uses this to suppress suspected bots (high
// request volume): the traffic is still recorded in the DB / Events log, but
// notifiers stay quiet so a scanner doesn't flood Slack/webhooks.
type NotifySuppressor interface {
	NotifySuppressed() bool
}
