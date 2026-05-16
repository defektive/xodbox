package smtp

import (
	"context"
	"io"
	"os"
	"sync"

	"github.com/defektive/xodbox/pkg/types"
	"github.com/emersion/go-smtp"
)

type Handler struct {
	name            string
	Listener        string
	dispatchChannel chan types.InteractionEvent
	//app             types.App

	mu     sync.Mutex
	server *smtp.Server
}

func NewHandler(handlerConfig map[string]string) types.Handler {

	listener := handlerConfig["listener"]

	return &Handler{
		name:     "SMTP",
		Listener: listener,
	}
}

func (h *Handler) Name() string {
	return h.name
}

func (h *Handler) Start(app types.App, eventChan chan types.InteractionEvent) error {

	h.dispatchChannel = eventChan
	s := smtp.NewServer(h)

	s.Addr = h.Listener
	s.Domain = "localhost"
	s.AllowInsecureAuth = true
	s.Debug = os.Stdout

	insecureTLSConfig, err := NewInsecureCert().TLSConfig("test.com")
	if err != nil {
		return err
	}
	s.TLSConfig = insecureTLSConfig

	h.mu.Lock()
	h.server = s
	h.mu.Unlock()

	lg().Info("Starting SMTP Server", "listener", h.Listener)
	return s.ListenAndServe()
}

// Stop shuts down the underlying *smtp.Server. ctx bounds how long
// in-flight sessions have to drain. Safe to call before Start or
// multiple times.
func (h *Handler) Stop(ctx context.Context) error {
	h.mu.Lock()
	s := h.server
	h.mu.Unlock()
	if s == nil {
		return nil
	}
	return s.Shutdown(ctx)
}

func (h *Handler) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &SMTPSession{
		handler: h,
		conn:    c,
	}, nil
}

type SMTPSession struct {
	handler *Handler
	conn    *smtp.Conn
}

func (s *SMTPSession) AuthPlain(username, password string) error {
	e := NewEvent(s, PasswordAuth)
	e.Dispatch(s.handler.dispatchChannel)
	return nil
}

func (s *SMTPSession) Mail(from string, opts *smtp.MailOptions) error {
	e := NewEvent(s, Mail)
	e.Dispatch(s.handler.dispatchChannel)
	return nil
}

func (s *SMTPSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	e := NewEvent(s, Rcpt)
	e.Dispatch(s.handler.dispatchChannel)
	return nil
}

func (s *SMTPSession) Data(r io.Reader) error {
	e := NewEvent(s, Data)
	e.Dispatch(s.handler.dispatchChannel)
	return nil
}

func (s *SMTPSession) Reset() {
	e := NewEvent(s, Reset)
	e.Dispatch(s.handler.dispatchChannel)
}

func (s *SMTPSession) Logout() error {
	e := NewEvent(s, Logout)
	e.Dispatch(s.handler.dispatchChannel)
	return nil
}
