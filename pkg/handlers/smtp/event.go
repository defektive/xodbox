package smtp

import (
	"fmt"
	"github.com/defektive/xodbox/pkg/types"
	"net/url"
	"strconv"
)

type Action int

// Declare related constants for each weekday starting with index 1
const (
	PasswordAuth Action = iota + 1 // EnumIndex = 1
	Mail         Action = iota + 1 // EnumIndex = 1
	Rcpt         Action = iota + 1 // EnumIndex = 1
	Data         Action = iota + 1 // EnumIndex = 1
	Reset        Action = iota + 1 // EnumIndex = 1
	Logout       Action = iota + 1 // EnumIndex = 1
)

// String - Creating common behavior - give the type a String function
func (w Action) String() string {
	return [...]string{"PasswordAuth", "Mail"}[w-1]
}

type Event struct {
	*types.BaseEvent
	ctx    *SMTPSession
	action Action
}

func NewEvent(ctx *SMTPSession, action Action) *Event {

	ctx.conn.Conn().RemoteAddr()

	remoteAddrURL := fmt.Sprintf("smtp://%s", ctx.conn.Conn().RemoteAddr())
	parsedURL, _ := url.Parse(remoteAddrURL)
	portNum, _ := strconv.Atoi(parsedURL.Port())

	return &Event{
		BaseEvent: &types.BaseEvent{
			RemoteAddr:       parsedURL.Hostname(),
			RemotePortNumber: portNum,
		},
		ctx:    ctx,
		action: action,
	}
}
