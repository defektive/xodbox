package ssh

import (
	"io"

	"github.com/defektive/xodbox/pkg/types"
	"github.com/gliderlabs/ssh"
)

type Handler struct {
	name            string
	Listener        string
	dispatchChannel chan types.InteractionEvent
	//app             types.App
}

func NewHandler(handlerConfig map[string]string) types.Handler {

	listener, ok := handlerConfig["listener"]
	if !ok {
		listener = ":22"
	}

	return &Handler{
		name:     "SSH",
		Listener: listener,
	}
}

func (h Handler) Name() string {
	return h.name
}

func (h Handler) Start(app types.App, eventChan chan types.InteractionEvent) error {
	h.dispatchChannel = eventChan
	ssh.Handle(func(s ssh.Session) {
		if _, err := io.WriteString(s, "This account is currently not available\n"); err != nil {
			lg().Debug("ssh session write failed", "err", err)
		}
	})

	lg().Info("starting ssh handler", "listener", h.Listener)
	return ssh.ListenAndServe(
		h.Listener,
		nil,
		ssh.PasswordAuth(func(ctx ssh.Context, password string) bool {
			lg().Debug("authenticating ssh handler", "username", ctx.User(), "password", password)
			e := NewEvent(ctx, PasswordAuth)
			e.Dispatch(h.dispatchChannel)
			return false
		}),

		ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			lg().Debug("authenticating ssh handler", "username", ctx.User(), "key", key.Type())
			e := NewEvent(ctx, KeyAuth)
			e.Dispatch(h.dispatchChannel)
			return false
		}),
	)
}
