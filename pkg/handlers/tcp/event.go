package tcp

import (
	"fmt"
	"net"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
	"github.com/defektive/xodbox/pkg/util"
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

// FilterString returns "TCP <ACTION> from <ip>", e.g.
// "TCP Data from 10.0.0.5".
func (e *Event) FilterString() string {
	return fmt.Sprintf("TCP %s from %s", e.action.String(), e.RemoteAddr)
}

// Interaction records the TCP event (any received bytes ride in Data) for the
// DB / web UI.
func (e *Event) Interaction() *model.Interaction {
	return &model.Interaction{
		RemoteAddr:  e.RemoteAddr,
		RemotePort:  fmt.Sprintf("%d", e.RemotePortNumber),
		Handler:     "tcp",
		Protocol:    "tcp",
		RequestType: e.action.String(),
		Data:        e.RawData,
	}
}

func NewEvent(ctx net.Conn, action Action, packet []byte) *Event {
	hostname, portNum := util.GetHostAndPortFromRemoteAddr(ctx.RemoteAddr().String())

	return &Event{
		BaseEvent: &types.BaseEvent{
			RemoteAddr:       hostname,
			RemotePortNumber: portNum,
			RawData:          packet,
		},
		ctx:    ctx,
		action: action,
	}
}
