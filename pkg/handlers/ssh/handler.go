package ssh

import (
	"context"
	"io"
	"sync"

	"github.com/defektive/xodbox/pkg/types"
	"github.com/gliderlabs/ssh"
)

type Handler struct {
	name            string
	Listener        string
	dispatchChannel chan types.InteractionEvent
	//app             types.App

	mu     sync.Mutex
	server *ssh.Server
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

func (h *Handler) Name() string {
	return h.name
}

func (h *Handler) Start(app types.App, eventChan chan types.InteractionEvent) error {
	h.dispatchChannel = eventChan

	srv := &ssh.Server{
		Addr: h.Listener,
		Handler: func(s ssh.Session) {
			if _, err := io.WriteString(s, "This account is currently not available\n"); err != nil {
				lg().Debug("ssh session write failed", "err", err)
			}
		},
		PasswordHandler: func(ctx ssh.Context, password string) bool {
			lg().Debug("authenticating ssh handler", "username", ctx.User(), "password", password)
			e := NewEvent(ctx, PasswordAuth)
			e.Dispatch(h.dispatchChannel)
			return false
		},
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			lg().Debug("authenticating ssh handler", "username", ctx.User(), "key", key.Type())
			e := NewEvent(ctx, KeyAuth)
			e.Dispatch(h.dispatchChannel)
			return false
		},
	}

	h.mu.Lock()
	h.server = srv
	h.mu.Unlock()

	lg().Info("starting ssh handler", "listener", h.Listener)
	return srv.ListenAndServe()
}

// Stop tells the underlying *ssh.Server to shut down. ctx bounds how
// long in-flight sessions have to drain. Safe to call before Start
// or multiple times.
func (h *Handler) Stop(ctx context.Context) error {
	h.mu.Lock()
	srv := h.server
	h.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}
