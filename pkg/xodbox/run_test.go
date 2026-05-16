package xodbox

import (
	"regexp"
	"testing"

	"github.com/defektive/xodbox/pkg/types"
)

type stubNotifier struct{ name string }

func (s *stubNotifier) Name() string                      { return s.name }
func (s *stubNotifier) Send(types.InteractionEvent) error { return nil }
func (s *stubNotifier) Filter() *regexp.Regexp            { return regexp.MustCompile(".*") }

func TestNewAppRegistersNotifiers(t *testing.T) {
	n1 := &stubNotifier{name: "a"}
	n2 := &stubNotifier{name: "b"}

	cfg := &Config{
		TemplateData: map[string]string{"k": "v"},
		Notifiers:    []types.Notifier{n1, n2},
	}

	app := NewApp(cfg)
	if app == nil {
		t.Fatal("NewApp returned nil")
	}
	if len(app.notificationHandlers) != 2 {
		t.Errorf("notificationHandlers len = %d, want 2", len(app.notificationHandlers))
	}
}

func TestRegisterNotificationHandlerAppends(t *testing.T) {
	app := NewApp(&Config{})
	app.RegisterNotificationHandler(&stubNotifier{name: "extra"})

	if len(app.notificationHandlers) != 1 {
		t.Errorf("len = %d, want 1", len(app.notificationHandlers))
	}
	if app.notificationHandlers[0].Name() != "extra" {
		t.Errorf("name = %q, want extra", app.notificationHandlers[0].Name())
	}
}

func TestGetTemplateDataReturnsClone(t *testing.T) {
	cfg := &Config{TemplateData: map[string]string{"k": "v"}}
	app := NewApp(cfg)

	td := app.GetTemplateData()
	if td["k"] != "v" {
		t.Errorf("template data missing key, got %v", td)
	}

	// Mutating the returned map must not affect the underlying config.
	td["k"] = "mutated"
	if cfg.TemplateData["k"] != "v" {
		t.Error("GetTemplateData should return a clone, not the underlying map")
	}
}
