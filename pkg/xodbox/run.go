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

func NewApp(config *Config) *App {

	newApp := &App{
		appConfig:            config,
		eventChan:            make(chan types.InteractionEvent),
		notificationHandlers: []types.Notifier{},
		stop:                 make(chan struct{}),
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
	notificationHandlers []types.Notifier

	// stop is closed once by Shutdown to unblock waitForEvents.
	stop chan struct{}
}

func (x *App) Run() {
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

// persistInteraction stores an event as an Interaction when the event supports
// it (implements types.Persistable), so every handler's activity — not just
// httpx — shows up in the DB and the web UI. Writes run on the single event-loop
// goroutine, which serialises them (the pure-Go SQLite driver dislikes
// concurrent writers). A nil record means the event opted out of persistence.
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
			// Persist every event, then dispatch to notifiers — unless the event
			// opts out of notification (e.g. a suspected bot), which stays
			// recorded but silent.
			persistInteraction(newEvent)
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
