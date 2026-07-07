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
	conns    map[net.Conn]struct{}
	done     chan struct{}
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

// Stop closes the listening socket so Start's Accept loop exits, then
// closes every in-flight connection so blocked reads return and their
// handleConn goroutines exit. Closing h.done lets any dispatch send that
// is parked on a full channel fall through instead of leaking. Safe to
// call multiple times and before Start.
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

// handleConn reads bytes from a single accepted connection until the
// peer closes (EOF) or read fails. Each chunk produces a DataRecv
// event carrying the bytes actually read; Connect fires on accept and
// Disconnect fires once the read loop exits.
func (h *Handler) handleConn(c net.Conn) {
	defer c.Close()
	lg().Debug("Accepted connection", "remote", c.RemoteAddr().String())

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

	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			// Copy the read window — buf is reused on the next Read,
			// and the slice is about to ride through a channel into
			// another goroutine.
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			h.send(done, NewEvent(c, DataRecv, chunk))
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				lg().Debug("tcp read finished", "err", err)
			}
			return
		}
	}
}

// send delivers an event without blocking past shutdown: once Stop
// closes done, a send parked on a full dispatch channel is abandoned so
// the goroutine can exit instead of leaking.
func (h *Handler) send(done <-chan struct{}, e types.InteractionEvent) {
	select {
	case h.dispatchChannel <- e:
	case <-done:
	}
}
