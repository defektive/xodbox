package xodbox

import (
	"github.com/defektive/xodbox/pkg/types"
	"maps"
	"os"
)

func NewApp(config *Config) *App {

	newApp := &App{
		appConfig:            config,
		eventChan:            make(chan types.InteractionEvent),
		notificationHandlers: []types.Notifier{},
	}

	for _, notifier := range config.Notifiers {
		lg().Debug("register notifier", "notifier", notifier.Name())
		newApp.RegisterNotificationHandler(notifier)
	}

	return newApp
}

type App struct {
	appConfig            *Config
	eventChan            chan types.InteractionEvent
	notificationHandlers []types.Notifier
}

func (x *App) Run() {
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

func (x *App) RegisterNotificationHandler(n types.Notifier) {
	x.notificationHandlers = append(x.notificationHandlers, n)
}

func (x *App) GetTemplateData() map[string]string {
	return maps.Clone(x.appConfig.TemplateData)
}

func (x *App) waitForEvents() {
	lg().Debug("Waiting for events...")
	for {
		newEvent := <-x.eventChan
		for _, h := range x.notificationHandlers {
			go h.Send(newEvent)
		}
	}
}
