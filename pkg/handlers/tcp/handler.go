package tcp

import (
	"github.com/defektive/xodbox/pkg/types"
	"io"
	"log"
	"net"
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
		log.Fatal(err)
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			lg().Debug("Accepted connection", "remote", c.RemoteAddr().String())
			h.dispatchChannel <- NewEvent(c, Connect)

			packet := make([]byte, 4096)
			tmp := make([]byte, 4096)
			defer c.Close()
			for {
				_, err := c.Read(tmp)
				if err != nil {
					if err != io.EOF {
						lg().Error("error reading from connection", "err", err)
					}

					h.dispatchChannel <- NewEvent(c, Disconnect)
					break
				}
				packet = append(packet, tmp...)
				h.dispatchChannel <- NewEvent(c, DataRecv)
			}
			num, _ := c.Write([]byte{0x90})

			h.dispatchChannel <- NewEvent(c, DataRecv)
			lg().Info("Send data", "num", num)
		}(c)
	}
}
