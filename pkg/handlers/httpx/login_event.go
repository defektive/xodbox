package httpx

import (
	"fmt"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
)

// LoginEvent is emitted on a successful admin-UI login when notify_logins is
// enabled. Unlike ordinary admin traffic (which never produces events), a login
// flows through the normal pipeline so it is recorded in the Events log and
// delivered to notifiers whose Filter matches. Its FilterString has the
// canonical "HTTPX Login <user> from <ip>" shape, so an operator can select it
// with a filter like "^HTTPX Login".
type LoginEvent struct {
	*types.BaseEvent
	username    string
	interaction *model.Interaction
}

// NewLoginEvent builds a login event for the given admin username and source.
func NewLoginEvent(username, ip, userAgent string) *LoginEvent {
	details := fmt.Sprintf("admin login: %s", username)
	return &LoginEvent{
		BaseEvent: &types.BaseEvent{
			RemoteAddr:      ip,
			UserAgentString: userAgent,
			RawData:         []byte(details),
		},
		username: username,
		interaction: &model.Interaction{
			RemoteAddr:    ip,
			Handler:       "httpx",
			Protocol:      "http",
			RequestType:   "LOGIN",
			RequestTarget: username,
			UserAgent:     userAgent,
			Data:          []byte(details),
		},
	}
}

// Details renders the human-readable line used by chat notifiers.
func (e *LoginEvent) Details() string {
	return fmt.Sprintf("HTTPX admin login: %s from %s", e.username, e.RemoteIP())
}

// FilterString returns "HTTPX Login <user> from <ip>" so notifier filters can
// select admin logins across handlers with a single regex.
func (e *LoginEvent) FilterString() string {
	return fmt.Sprintf("HTTPX Login %s from %s", e.username, e.RemoteIP())
}

// Interaction returns the record persisted for the login (see types.Persistable).
func (e *LoginEvent) Interaction() *model.Interaction {
	return e.interaction
}

// Dispatch sends the concrete LoginEvent (not the embedded BaseEvent) onto the
// event channel, so downstream type assertions on the outer type still work.
func (e *LoginEvent) Dispatch(cc chan types.InteractionEvent) {
	go func() {
		cc <- e
	}()
}
