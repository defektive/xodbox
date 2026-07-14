package xodbox

import (
	"context"
	"maps"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
)

// shutdownTimeout caps how long the app will wait for handlers to
// drain after a SIGINT/SIGTERM before returning anyway.
const shutdownTimeout = 10 * time.Second

// persistQueueSize bounds the buffer of interactions waiting to be written by
// the single persister goroutine. When it fills (e.g. a write-locked DB under a
// flood), new records are dropped rather than stalling the event loop.
const persistQueueSize = 1024

func NewApp(config *Config) *App {

	// Build the global ignore/drop list from defaults. A bad CIDR or regex is
	// fatal: silently dropping (or keeping) everything is worse than failing
	// loudly at startup.
	ignore, err := newIgnoreRule(config.TemplateData)
	if err != nil {
		lg().Error("invalid ignore rule in config defaults", "err", err)
		os.Exit(1)
	}
	if ignore.active() {
		lg().Info("global ignore list active; matching events will be dropped (not persisted or notified)")
	}

	newApp := &App{
		appConfig:            config,
		eventChan:            make(chan types.InteractionEvent),
		persistChan:          make(chan types.InteractionEvent, persistQueueSize),
		notificationHandlers: []types.Notifier{},
		ignore:               ignore,
		stop:                 make(chan struct{}),
	}

	if len(config.Workers) > 0 {
		newApp.workerEngine = newWorkerEngine(config.Workers)
	}

	for _, notifier := range config.Notifiers {
		lg().Debug("register notifier", "notifier", notifier.Name())
		newApp.RegisterNotificationHandler(notifier)
	}

	// Give every handler that implements types.Seeder a chance to
	// populate its own DB state. Done here (not in Run) so non-Run
	// entry points like `xodbox payload dump` still see the seeded
	// payload set.
	for _, h := range config.Handlers {
		if s, ok := h.(types.Seeder); ok {
			lg().Debug("seeding handler", "handler", h.Name())
			if err := s.Seed(); err != nil {
				lg().Error("handler seed failed", "handler", h.Name(), "err", err)
			}
		}
	}

	return newApp
}

type App struct {
	appConfig            *Config
	eventChan            chan types.InteractionEvent
	persistChan          chan types.InteractionEvent
	notificationHandlers []types.Notifier

	// ignore drops events from configured noisy sources before they are
	// persisted or dispatched. Never nil (newIgnoreRule always returns a rule).
	ignore *ignoreRule

	// stop is closed once by Shutdown to unblock waitForEvents.
	stop chan struct{}

	// workerEngine runs periodic background jobs. Nil when no workers are configured.
	workerEngine *workerEngine
}

func (x *App) Run() {
	// The persister writes to the DB off the event loop so a slow/locked SQLite
	// write never delays notifier delivery.
	go x.runPersister()

	if x.workerEngine != nil {
		x.workerEngine.start()
	}

	for _, h := range x.appConfig.Handlers {
		lg().Debug("Running handler", "handler", h)
		go func(h types.Handler) {
			err := h.Start(x, x.eventChan)
			if err != nil {
				lg().Error("error starting handler", "err", err, "handler", h)
				os.Exit(1)
			}
		}(h)
	}

	// Translate SIGINT/SIGTERM into a graceful shutdown: cancel each
	// handler with a bounded context, then return from waitForEvents.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		lg().Info("shutdown signal received", "signal", sig.String())
		x.Shutdown()
	}()

	x.waitForEvents()
}

// Shutdown stops every registered handler and unblocks Run.
// Idempotent — multiple callers see only the first stop fire.
func (x *App) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	for _, h := range x.appConfig.Handlers {
		if err := h.Stop(ctx); err != nil {
			lg().Warn("handler stop returned error", "handler", h.Name(), "err", err)
		}
	}

	if x.workerEngine != nil {
		x.workerEngine.stop()
	}

	// Close stop at most once so concurrent Shutdown callers don't
	// panic on a double close.
	defer func() {
		_ = recover()
	}()
	close(x.stop)
}

func (x *App) RegisterNotificationHandler(n types.Notifier) {
	x.notificationHandlers = append(x.notificationHandlers, n)
}

func (x *App) GetTemplateData() map[string]string {
	return maps.Clone(x.appConfig.TemplateData)
}

// runPersister is the single writer goroutine: it drains persistChan and stores
// each event, off the event loop, so a slow/locked SQLite write never delays
// notifier dispatch. One writer keeps the pure-Go SQLite driver (which dislikes
// concurrent writers) happy.
func (x *App) runPersister() {
	for {
		select {
		case <-x.stop:
			return
		case e := <-x.persistChan:
			persistInteraction(e)
		}
	}
}

// persistInteraction stores an event as an Interaction when the event supports
// it (implements types.Persistable), so every handler's activity — not just
// httpx — shows up in the DB and the web UI. A nil record means the event opted
// out of persistence.
func persistInteraction(e types.InteractionEvent) {
	p, ok := e.(types.Persistable)
	if !ok {
		return
	}
	i := p.Interaction()
	if i == nil {
		return
	}
	if tx := model.DB().Create(i); tx.Error != nil {
		lg().Error("failed to persist interaction", "err", tx.Error, "handler", i.Handler)
		return
	}
	// Fan out to any live subscribers (the admin UI's realtime stream).
	model.PublishInteraction(i)
}

func (x *App) waitForEvents() {
	lg().Debug("Waiting for events...")
	for {
		select {
		case <-x.stop:
			lg().Debug("event loop shutting down")
			return
		case newEvent := <-x.eventChan:
			// Drop events from configured noisy sources entirely: no DB row, no
			// notification, no log spam. This is the escape hatch for a known
			// callout (e.g. a leftover beacon hammering the server every second)
			// that would otherwise flood both the Events log and the database.
			if x.ignore.Matches(newEvent) {
				lg().Debug("ignoring event (matched ignore list)", "details", newEvent.Details())
				continue
			}
			// Hand the event to the persister (non-blocking so a write backlog
			// can't stall the loop), then dispatch to notifiers — unless the
			// event opts out of notification (e.g. a suspected bot), which stays
			// recorded but silent.
			select {
			case x.persistChan <- newEvent:
			default:
				lg().Warn("persist queue full; dropping interaction record")
			}
			if s, ok := newEvent.(types.NotifySuppressor); ok && s.NotifySuppressed() {
				continue
			}
			for _, h := range x.notificationHandlers {
				go func(h types.Notifier) {
					if err := h.Send(newEvent); err != nil {
						lg().Error("notifier send failed", "notifier", h.Name(), "err", err)
					}
				}(h)
			}
		}
	}
}
