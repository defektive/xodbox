package types

import "regexp"

type App interface {
	Run()
	RegisterNotificationHandler(func(InteractionEvent))
}

type InteractionEvent interface {
	Details() string
	RemoteIP() string
	RemotePort() int
	UserAgent() string
	Data() string
}

type Handler interface {
	Name() string
	Start(eventChan chan InteractionEvent) error
}

type Notifier interface {
	Name() string
	Endpoint() string
	Send(InteractionEvent) error
	Payload(InteractionEvent) ([]byte, error)
	Filter() *regexp.Regexp
}
