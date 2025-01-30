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

type BaseEvent struct {
	RemoteAddr       string
	RemotePortNumber int
	UserAgentString  string
	RawData          []byte
}

func (e *BaseEvent) Details() string {
	return "Default Event"
}

func (e *BaseEvent) RemoteIP() string {
	return e.RemoteAddr
}

func (e *BaseEvent) RemotePort() int {
	return e.RemotePortNumber
}

func (e *BaseEvent) UserAgent() string {
	return e.UserAgentString
}

func (e *BaseEvent) Data() string {
	return string(e.RawData)
}
