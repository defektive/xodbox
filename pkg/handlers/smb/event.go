package smb

import (
	"fmt"
	"net"

	"github.com/defektive/xodbox/pkg/types"
	"github.com/defektive/xodbox/pkg/util"
)

type Action int

const (
	Connect    Action = iota + 1 // 1
	Negotiate                    // 2
	Auth                         // 3
	Disconnect                   // 4
)

// String - give the type a String function
func (a Action) String() string {
	return [...]string{"Connect", "Negotiate", "Auth", "Disconnect"}[a-1]
}

// Event is an SMB interaction. For Auth events RawData carries the
// captured NetNTLMv2 hash in hashcat mode 5600 format; Account holds
// the DOMAIN\User the client authenticated as.
type Event struct {
	*types.BaseEvent
	action  Action
	Account string
}

func (e *Event) Details() string {
	if e.action == Auth {
		return fmt.Sprintf("SMB Interaction Event: %s %d %s %s", e.RemoteAddr, e.RemotePortNumber, e.action.String(), e.Account)
	}
	return fmt.Sprintf("SMB Interaction Event: %s %d %s", e.RemoteAddr, e.RemotePortNumber, e.action.String())
}

// FilterString returns "SMB <ACTION> [account] from <ip>", e.g.
// "SMB Auth CORP\\alice from 10.0.0.5".
func (e *Event) FilterString() string {
	if e.action == Auth && e.Account != "" {
		return fmt.Sprintf("SMB %s %s from %s", e.action, e.Account, e.RemoteAddr)
	}
	return fmt.Sprintf("SMB %s from %s", e.action, e.RemoteAddr)
}

// Dispatch sends the concrete *Event (not the embedded *BaseEvent) onto
// the channel so notifiers see this type's Details()/Data().
func (e *Event) Dispatch(cc chan types.InteractionEvent) {
	go func() {
		cc <- e
	}()
}

func NewEvent(c net.Conn, action Action, data []byte) *Event {
	hostname, portNum := util.GetHostAndPortFromRemoteAddr(c.RemoteAddr().String())

	return &Event{
		BaseEvent: &types.BaseEvent{
			RemoteAddr:       hostname,
			RemotePortNumber: portNum,
			RawData:          data,
		},
		action: action,
	}
}
