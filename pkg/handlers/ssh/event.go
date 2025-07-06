package ssh

import (
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

func NewEvent(ctx ssh.Context, action Action) *Event {
	hostname, portNum := util.HostAndPortFromRemoteAddr(ctx.RemoteAddr().String())

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
