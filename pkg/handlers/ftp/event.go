package ftp

import (
	"fmt"
	"github.com/defektive/xodbox/pkg/types"
	"github.com/gliderlabs/ssh"
	"net/url"
	"strconv"
)

type Action int

// Declare related constants for each weekday starting with index 1
const (
	AuthSuccess Action = iota + 1 // EnumIndex = 1
	AuthFail    Action = iota + 1 // EnumIndex = 1
	Logout      Action = iota + 1 // EnumIndex = 1
	ListFiles
	FileOpen    = iota + 1 // EnumIndex = 1
	FileRead    = iota + 1 // EnumIndex = 1
	FileWrite   = iota + 1 // EnumIndex = 1
	FileReadDir = iota + 1 // EnumIndex = 1
	FileDelete  = iota + 1 // EnumIndex = 1
)

// String - Creating common behavior - give the type a String function
func (w Action) String() string {
	return [...]string{"PasswordAuth", "KeyAuth"}[w-1]
}

type Event struct {
	*types.BaseEvent
	ctx    ssh.Context
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
