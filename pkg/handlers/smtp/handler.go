package smtp

import (
	"github.com/defektive/xodbox/pkg/types"
	"github.com/emersion/go-smtp"
	"io"
	"log"
	"os"
)

type Handler struct {
	name            string
	Listener        string
	dispatchChannel chan types.InteractionEvent
	//app             types.App
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

	log.Println("Starting SMTP server at", s.Addr)
	return s.ListenAndServe()

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
