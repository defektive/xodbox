package types

import (
	"context"
	"regexp"
)

type App interface {
	Run()
	RegisterNotificationHandler(Notifier)
	GetTemplateData() map[string]string
	Reload() error
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

// SinkHitProvider is an optional interface implemented by events that
// represent a sink hit — an inbound interaction matching a notify-enabled
// sink. Notifiers type-assert to it for enriched formatting (sink slug,
// description, and a link to the sink).
type SinkHitProvider interface {
	SinkSlug() string
	SinkDescription() string
	SinkLink() string
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

// ConfigFile is the deserialized YAML config. It lives in types so packages
// on both sides of the handler↔app boundary can reference it without cycles.
type ConfigFile struct {
	Defaults  map[string]string   `yaml:"defaults"  json:"defaults"`
	Handlers  []map[string]string `yaml:"handlers"  json:"handlers"`
	Notifiers []map[string]string `yaml:"notifiers" json:"notifiers"`
	Workers   []map[string]string `yaml:"workers"   json:"workers"`
}

// ConfigAware is implemented by handlers that expose a config management API.
// The app injects a ConfigOps after construction.
type ConfigAware interface {
	SetConfigOps(ConfigOps)
}

// ConfigOps provides config file operations to handlers that expose a
// management API (the HTTPX admin console). Implemented by the xodbox package
// and injected into the handler at construction time.
type ConfigOps interface {
	FilePath() string
	Read() (*ConfigFile, error)
	Write(cf *ConfigFile) error
	Validate(cf *ConfigFile) []string
	HandlerNames() []string
	NotifierNames() []string
	WorkerNames() []string
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
