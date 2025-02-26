package app

import (
	"github.com/defektive/xodbox/pkg/types"
	"os"
)

func NewXodbox(config *AppConfig) *Xodbox {

	xodbox := &Xodbox{
		appConfig:            config,
		eventChan:            make(chan types.InteractionEvent),
		notificationHandlers: []types.Notifier{},
	}

	for _, notifier := range config.Notifiers {
		lg().Debug("notifier: ", "notifier", notifier.Name())
		xodbox.RegisterNotificationHandler(notifier)
	}

	return xodbox
}

type Xodbox struct {
	appConfig            *AppConfig
	eventChan            chan types.InteractionEvent
	notificationHandlers []types.Notifier
}

func (x *Xodbox) Run() {
	for _, h := range x.appConfig.Handlers {
		lg().Debug("Running handler", "handler", h)
		go (func() {
			err := h.Start(x, x.eventChan)
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

func (x *Xodbox) GetTemplateData() map[string]string {
	return x.appConfig.TemplateData
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
