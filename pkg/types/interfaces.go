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
	// FilterString returns the canonical, handler-labelled string a
	// notifier's Filter regex is matched against. It has the shape
	// "HANDLER ACTION DETAIL from IP[,IP...]" (e.g. "SMB Auth CORP\\alice
	// from 10.0.0.5"), so a single regex can select across every handler
	// (e.g. "^SMB Auth", "^DNS (A|AAAA) .*\\.evil\\.com"). The trailing IP
	// list is the unique source chain (X-Forwarded-For + peer for HTTP).
	FilterString() string
	Dispatch(cc chan InteractionEvent)
}

// CurlProvider is an optional interface implemented by events that can
// render a curl command reproducing the captured request (currently HTTP).
// Notifiers type-assert to it to append a copy-pasteable replay command —
// useful for turning an SSRF callback into a request you can re-run from
// the CLI. Events that don't implement it are simply rendered without one.
type CurlProvider interface {
	CurlCommand() string
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

// Worker is a periodic background job managed by the workflow engine.
// Schedule is a robfig/cron v3 expression: standard 5-field cron
// ("0 2 * * *"), shorthand ("@daily"), or interval ("@every 1h").
// Run is called once per tick; ctx is cancelled on shutdown.
// An error is logged but does not stop future ticks.
type Worker interface {
	Name() string
	Schedule() string
	Run(ctx context.Context) error
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
