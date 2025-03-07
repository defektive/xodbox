package ssh

import (
	"fmt"
	"github.com/defektive/xodbox/pkg/types"
	"github.com/gliderlabs/ssh"
	"net/url"
	"strconv"
)

type Event struct {
	*types.BaseEvent
	ctx ssh.Context
}

func NewEvent(ctx ssh.Context) *Event {

	remoteAddrURL := fmt.Sprintf("https://%s", ctx.RemoteAddr().String())
	parsedURL, _ := url.Parse(remoteAddrURL)
	portNum, _ := strconv.Atoi(parsedURL.Port())

	return &Event{
		BaseEvent: &types.BaseEvent{
			RemoteAddr:       parsedURL.Hostname(),
			RemotePortNumber: portNum,
			UserAgentString:  ctx.ClientVersion(),
		},
		ctx: ctx,
	}
}
