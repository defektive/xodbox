package tcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/defektive/xodbox/pkg/types"
)

type Handler struct {
	name            string
	Listener        string
	dispatchChannel chan types.InteractionEvent
	//app             types.App

	mu       sync.Mutex
	listener net.Listener
	stopping bool
}

func NewHandler(handlerConfig map[string]string) types.Handler {

	listener := handlerConfig["listener"]

	return &Handler{
		name:     "TCP",
		Listener: listener,
	}
}

func (h *Handler) Name() string {
	return h.name
}

func (h *Handler) Start(app types.App, eventChan chan types.InteractionEvent) error {
	h.dispatchChannel = eventChan
	lg().Info("Starting TCP Server", "listener", h.Listener)

	l, err := net.Listen("tcp4", h.Listener)
	if err != nil {
		return fmt.Errorf("tcp listen %q: %w", h.Listener, err)
	}
	h.mu.Lock()
	h.listener = l
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

// Stop closes the listening socket so Start's Accept loop exits.
// In-flight handleConn goroutines drain naturally as their peers
// close. Safe to call multiple times and before Start.
func (h *Handler) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopping = true
	if h.listener == nil {
		return nil
	}
	return h.listener.Close()
}

// handleConn reads bytes from a single accepted connection until the
// peer closes (EOF) or read fails. Each chunk produces a DataRecv
// event carrying the bytes actually read; Connect fires on accept and
// Disconnect fires once the read loop exits.
func (h *Handler) handleConn(c net.Conn) {
	defer c.Close()
	lg().Debug("Accepted connection", "remote", c.RemoteAddr().String())

	h.dispatchChannel <- NewEvent(c, Connect, nil)
	defer func() {
		h.dispatchChannel <- NewEvent(c, Disconnect, nil)
	}()

	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			// Copy the read window — buf is reused on the next Read,
			// and the slice is about to ride through a channel into
			// another goroutine.
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			h.dispatchChannel <- NewEvent(c, DataRecv, chunk)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				lg().Debug("tcp read finished", "err", err)
			}
			return
		}
	}
}
