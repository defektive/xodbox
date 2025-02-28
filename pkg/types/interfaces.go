package types

import "regexp"

type App interface {
	Run()
	RegisterNotificationHandler(Notifier)
	GetTemplateData() map[string]string
}

type InteractionEvent interface {
	Details() string
	RemoteIP() string
	RemotePort() int
	UserAgent() string
	Data() string
	IsApp() bool
	Dispatch(cc chan InteractionEvent)
}

type Handler interface {
	Name() string
	Start(App, chan InteractionEvent) error
}

type Notifier interface {
	Name() string
	Send(InteractionEvent) error
	Filter() *regexp.Regexp
}

type NotifierBase struct {
	Name   string
	Filter string
}

type NotifierWebhook struct {
	NotifierBase
	URL string
}

type NotifierChat struct {
	NotifierWebhook
	Channel   string
	User      string
	UserImage string
}
