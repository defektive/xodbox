package types

import (
	"context"
	"regexp"
)

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
	Dispatch(cc chan InteractionEvent)
}

// Handler is a listening protocol implementation (HTTP, SMTP, DNS, ...).
// Start blocks serving requests; Stop should release the listening
// socket and any goroutines the handler owns. ctx provides a deadline
// for in-flight requests to drain. Stop must be safe to call even if
// Start was never invoked or has already returned.
type Handler interface {
	Name() string
	Start(App, chan InteractionEvent) error
	Stop(ctx context.Context) error
}

// Seeder is an optional interface implemented by handlers that need
// to populate their own database state (e.g. payload templates)
// before any requests are served. App.Run calls Seed on each
// implementing handler exactly once, after the DB is connected and
// before any Start. Seed must be idempotent.
type Seeder interface {
	Seed() error
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
