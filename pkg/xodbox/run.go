package xodbox

import (
	"context"
	"fmt"
	"maps"
	"os"
	"os/signal"
	"strings"
	"sync"
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

	cfgOps := NewConfigOps()

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
		if ca, ok := h.(types.ConfigAware); ok {
			ca.SetConfigOps(cfgOps)
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

	// reloadMu serialises Reload calls so two concurrent triggers (e.g.
	// SIGHUP + API PUT) don't race on the handler stop/start cycle.
	reloadMu sync.Mutex
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

	// Translate OS signals: SIGINT/SIGTERM → graceful shutdown;
	// SIGHUP → reload config from disk without full process restart.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				lg().Info("SIGHUP received, reloading config")
				if err := x.Reload(); err != nil {
					lg().Error("config reload failed", "err", err)
				}
				continue
			}
			lg().Info("shutdown signal received", "signal", sig.String())
			x.Shutdown()
			return
		}
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

// Reload stops all running handlers/workers, reloads config from disk,
// and starts the new handlers/workers. The event loop and persister keep
// running across the reload. Returns an error if the new config is
// invalid; in that case the old handlers are already stopped — a second
// Reload with a fixed config will recover.
func (x *App) Reload() error {
	x.reloadMu.Lock()
	defer x.reloadMu.Unlock()

	lg().Info("reloading config", "path", ConfigFilePath)

	newCf, err := ConfigFromFile(ConfigFilePath)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	if errs := ValidateConfigFile(newCf); len(errs) > 0 {
		return fmt.Errorf("config validation: %s", strings.Join(errs, "; "))
	}
	newConfig := ToConfig(newCf)

	newIgnore, err := newIgnoreRule(newConfig.TemplateData)
	if err != nil {
		return fmt.Errorf("invalid ignore rule: %w", err)
	}

	// --- point of no return: stop old, swap, start new ---

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, h := range x.appConfig.Handlers {
		if err := h.Stop(ctx); err != nil {
			lg().Warn("handler stop error during reload", "handler", h.Name(), "err", err)
		}
	}
	if x.workerEngine != nil {
		x.workerEngine.stop()
		x.workerEngine = nil
	}

	x.appConfig = newConfig
	x.notificationHandlers = newConfig.Notifiers
	x.ignore = newIgnore

	cfgOps := NewConfigOps()
	for _, h := range newConfig.Handlers {
		if s, ok := h.(types.Seeder); ok {
			if err := s.Seed(); err != nil {
				lg().Error("handler seed failed during reload", "handler", h.Name(), "err", err)
			}
		}
		if ca, ok := h.(types.ConfigAware); ok {
			ca.SetConfigOps(cfgOps)
		}
	}

	if len(newConfig.Workers) > 0 {
		x.workerEngine = newWorkerEngine(newConfig.Workers)
		x.workerEngine.start()
	}

	for _, h := range newConfig.Handlers {
		go func(h types.Handler) {
			if err := h.Start(x, x.eventChan); err != nil {
				lg().Error("handler start failed after reload", "handler", h.Name(), "err", err)
			}
		}(h)
	}

	lg().Info("config reloaded successfully")
	return nil
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
// concurrent writers) happy. After persisting, it checks for notify-enabled
// sinks matching the interaction and dispatches sink-hit notifications.
func (x *App) runPersister() {
	for {
		select {
		case <-x.stop:
			return
		case e := <-x.persistChan:
			i := persistInteraction(e)
			if i != nil {
				x.dispatchSinkHits(e, i)
			}
		}
	}
}

// persistInteraction stores an event as an Interaction when the event supports
// it (implements types.Persistable), so every handler's activity — not just
// httpx — shows up in the DB and the web UI. Returns the stored record (nil
// when the event opted out of persistence or the write failed).
func persistInteraction(e types.InteractionEvent) *model.Interaction {
	p, ok := e.(types.Persistable)
	if !ok {
		return nil
	}
	i := p.Interaction()
	if i == nil {
		return nil
	}
	if tx := model.DB().Create(i); tx.Error != nil {
		lg().Error("failed to persist interaction", "err", tx.Error, "handler", i.Handler)
		return nil
	}
	// Fan out to any live subscribers (the admin UI's realtime stream).
	model.PublishInteraction(i)
	return i
}

// dispatchSinkHits checks whether the persisted interaction matches any
// notify-enabled sinks and, for each match, sends a sink-hit notification
// through all registered notifiers.
func (x *App) dispatchSinkHits(e types.InteractionEvent, i *model.Interaction) {
	sinks := model.NotifySinks(i)
	if len(sinks) == 0 {
		return
	}
	publicURL := x.appConfig.TemplateData["public_url"]
	for _, s := range sinks {
		hit := newSinkHitEvent(e, s, publicURL)
		for _, n := range x.notificationHandlers {
			go func(n types.Notifier) {
				if err := n.Send(hit); err != nil {
					lg().Error("sink hit notifier send failed", "notifier", n.Name(), "sink", s.Slug, "err", err)
				}
			}(n)
		}
	}
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
