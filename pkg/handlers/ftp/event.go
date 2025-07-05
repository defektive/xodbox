package ftp

import (
	"fmt"
	"github.com/defektive/xodbox/pkg/types"
	"net/url"
	"strconv"
)

type Action int

// Declare related constants for each weekday starting with index 1
const (
	AuthSuccess Action = iota + 1 // EnumIndex = 1
	AuthFail    Action = iota + 1 // EnumIndex = 1
	Logout      Action = iota + 1 // EnumIndex = 1
	ListFiles   Action = iota + 1
	FileOpen    Action = iota + 1 // EnumIndex = 1
	FileRead    Action = iota + 1 // EnumIndex = 1
	FileWrite   Action = iota + 1 // EnumIndex = 1
	FileReadDir Action = iota + 1 // EnumIndex = 1
	FileDelete  Action = iota + 1 // EnumIndex = 1
)

// String - Creating common behavior - give the type a String function
func (w Action) String() string {
	return [...]string{
		"AuthSuccess",
		"AuthFail",
		"Logout",
		"ListFiles",
		"FileOpen",
		"FileRead",
		"FileWrite",
		"FileReadDir",
		"FileDelete",
	}[w-1]
}

type Event struct {
	*types.BaseEvent
	action Action
}

func NewEvent(remoteAddr string, action Action) *Event {

	remoteAddrURL := fmt.Sprintf("https://%s", remoteAddr)
	parsedURL, _ := url.Parse(remoteAddrURL)
	portNum, _ := strconv.Atoi(parsedURL.Port())

	return &Event{
		BaseEvent: &types.BaseEvent{
			RemoteAddr:       parsedURL.Hostname(),
			RemotePortNumber: portNum,
		},
		action: action,
	}
}

func (e *Event) Details() string {
	return fmt.Sprintf("FTP: event from %s", e.BaseEvent.RemoteAddr)
}
