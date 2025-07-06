package tcp

import (
	"fmt"
	"github.com/defektive/xodbox/pkg/types"
	"github.com/defektive/xodbox/pkg/util"
	"net"
)

type Action int

// Declare related constants for each weekday starting with index 1
const (
	Connect    Action = iota + 1 // EnumIndex = 1
	DataRecv   Action = iota + 1 // EnumIndex = 1
	Disconnect Action = iota + 1 // EnumIndex = 1
)

// String - Creating common behavior - give the type a String function
func (w Action) String() string {
	return [...]string{"Connection", "Data", "Disconnection"}[w-1]
}

type Event struct {
	*types.BaseEvent
	ctx    net.Conn
	action Action
}

func (e *Event) Details() string {
	return fmt.Sprintf("TCP Interaction Event: %s %d %s", e.RemoteAddr, e.RemotePortNumber, e.action.String())
}

func NewEvent(ctx net.Conn, action Action, packet []byte) *Event {
	hostname, portNum := util.HostAndPortFromRemoteAddr(ctx.RemoteAddr().String())

	return &Event{
		BaseEvent: &types.BaseEvent{
			RemoteAddr:       hostname,
			RemotePortNumber: portNum,
		},
		ctx:    ctx,
		action: action,
	}
}
