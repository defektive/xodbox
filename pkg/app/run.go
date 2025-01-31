package app

import (
	"github.com/defektive/xodbox/pkg/app/types"
	"os"
)

func NewXodbox() *Xodbox {
	return &Xodbox{
		eventChan: make(chan types.InteractionEvent),
		notificationHandlers: []types.Notifier{},
	}
}

type Xodbox struct {
	eventChan chan types.InteractionEvent
	notificationHandlers []types.Notifier
}

func (x *Xodbox) Run(handlers []types.Handler) {

	for _, h := range handlers {
		lg().Debug("Running handler", "handler", h)
		go (func() {
			err := h.Start(x.eventChan)
			if err != nil {
				lg().Error("error starting handler", "err", err, "handler", h)
				os.Exit(1)
			}
		})()
	}

	x.waitForEvents()
}

func (x *Xodbox) RegisterNotificationHandler(n types.Notifier) {
	x.notificationHandlers = append(x.notificationHandlers, n)
}

func (x *Xodbox) waitForEvents() {
	lg().Debug("Waiting for events...")
	for {
		newEvent := <-x.eventChan
		for _, h := range x.notificationHandlers {
			go h.Send(newEvent)
		}
	}
}
