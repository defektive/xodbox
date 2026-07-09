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

// Stop closes the underlying *smtp.Server immediately: its listeners and
// any active connections. Safe to call before Start or multiple times.
//
// We use Close rather than the graceful Shutdown(ctx) on purpose:
// go-smtp's Shutdown spawns a `wg.Wait()` goroutine that races the
// running Serve loop under the race detector (go-smtp v0.24.0). Close does
// the same teardown without that goroutine, and immediate close matches
// the other handlers (tcp, smb). ctx is unused.
func (h *Handler) Stop(ctx context.Context) error {
	_ = ctx
	h.mu.Lock()
	s := h.server
	h.server = nil
	h.mu.Unlock()
	if s == nil {
		return nil
	}
	return s.Close()
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
	// Drain the message body so it is captured on the event and the
	// protocol exchange completes; previously r was ignored and the
	// message content was silently dropped.
	if b, err := io.ReadAll(r); err != nil {
		lg().Debug("smtp data read failed", "err", err)
	} else {
		e.RawData = b
	}
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
