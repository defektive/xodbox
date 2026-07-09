package ssh

import (
	"fmt"

	"github.com/defektive/xodbox/pkg/types"
	"github.com/defektive/xodbox/pkg/util"
	"github.com/gliderlabs/ssh"
)

type Action int

// Declare related constants for each weekday starting with index 1
const (
	PasswordAuth Action = iota + 1 // EnumIndex = 1
	KeyAuth      Action = iota + 1 // EnumIndex = 1
)

// String - Creating common behavior - give the type a String function
func (w Action) String() string {
	return [...]string{"PasswordAuth", "KeyAuth"}[w-1]
}

type Event struct {
	*types.BaseEvent
	//ctx    ssh.Context
	user   string
	action Action
}

// Dispatch overrides the promoted BaseEvent.Dispatch so the outer SSH
// Event (and its concrete Details() / action) is delivered on the
// channel rather than the embedded BaseEvent pointer.
func (e *Event) Dispatch(cc chan types.InteractionEvent) {
	go func() {
		cc <- e
	}()
}

func (e *Event) Details() string {
	return fmt.Sprintf("SSH: %s from %s (%s)", e.action, e.user, e.RemoteAddr)
}

// FilterString returns "SSH <ACTION> <user> from <ip>", e.g.
// "SSH PasswordAuth root from 10.0.0.5".
func (e *Event) FilterString() string {
	return fmt.Sprintf("SSH %s %s from %s", e.action, e.user, e.RemoteAddr)
}

func NewEvent(ctx ssh.Context, action Action) *Event {
	hostname, portNum := util.GetHostAndPortFromRemoteAddr(ctx.RemoteAddr().String())

	return &Event{
		BaseEvent: &types.BaseEvent{
			RemoteAddr:       hostname,
			RemotePortNumber: portNum,
			UserAgentString:  ctx.ClientVersion(),
		},
		//ctx:    ctx,
		user:   ctx.User(),
		action: action,
	}
}
