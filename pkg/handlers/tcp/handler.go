package tcp

import (
	"fmt"
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
			h.dispatchChannel <- NewEvent(c, Connect)

			packet := make([]byte, 4096)
			tmp := make([]byte, 4096)
			defer c.Close()
			for {
				_, err := c.Read(tmp)
				if err != nil {
					if err != io.EOF {
						fmt.Println("read error:", err)
					}

					h.dispatchChannel <- NewEvent(c, Disconnect)
					break
				}
				packet = append(packet, tmp...)
				h.dispatchChannel <- NewEvent(c, DataRecv)
			}
			num, _ := c.Write([]byte{0x90})

			h.dispatchChannel <- NewEvent(c, DataRecv)

			log.Printf("Wrote back %d bytes, the payload is %s\n", num, string(packet))

		}(c)
	}
}
