package xodbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestToConfigDefaultsFallback(t *testing.T) {
	// nil Defaults should populate canonical defaults.
	cf := &ConfigFile{}
	got := cf.ToConfig()

	if got.TemplateData["notify_filter"] != DefaultNotifyFilter {
		t.Errorf("notify_filter = %q, want %q", got.TemplateData["notify_filter"], DefaultNotifyFilter)
	}
	if got.TemplateData["notify_string"] != "l" {
		t.Errorf("notify_string = %q, want l", got.TemplateData["notify_string"])
	}
	if got.TemplateData["server_name"] != "BreakfastBot" {
		t.Errorf("server_name = %q, want BreakfastBot", got.TemplateData["server_name"])
	}
}

func TestToConfigUnknownHandlerIgnored(t *testing.T) {
	cf := &ConfigFile{
		Defaults: map[string]string{},
		Handlers: []map[string]string{
			{"handler": "DOES_NOT_EXIST", "listener": ":0"},
			{"handler": "TCP", "listener": ":0"},
		},
	}
	got := cf.ToConfig()
	if len(got.Handlers) != 1 {
		t.Errorf("Handlers len = %d, want 1 (unknown should be skipped)", len(got.Handlers))
	}
	if got.Handlers[0].Name() != "TCP" {
		t.Errorf("Handlers[0].Name() = %q, want TCP", got.Handlers[0].Name())
	}
}

func TestToConfigUnknownNotifierIgnored(t *testing.T) {
	cf := &ConfigFile{
		Defaults: map[string]string{},
		Notifiers: []map[string]string{
			{"notifier": "DOES_NOT_EXIST"},
			{"notifier": "app_log"},
		},
	}
	got := cf.ToConfig()
	if len(got.Notifiers) != 1 {
		t.Errorf("Notifiers len = %d, want 1 (unknown should be skipped)", len(got.Notifiers))
	}
}

func TestConfigFromFileFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.yaml")
	yaml := `
defaults:
  notify_string: from-disk
handlers:
  - handler: TCP
    listener: :0
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cf, err := configFromFile(path)
	if err != nil {
		t.Fatalf("configFromFile err: %v", err)
	}
	if cf.Defaults["notify_string"] != "from-disk" {
		t.Errorf("notify_string = %q, want from-disk", cf.Defaults["notify_string"])
	}
	if len(cf.Handlers) != 1 || cf.Handlers[0]["handler"] != "TCP" {
		t.Errorf("Handlers = %v, want one TCP entry", cf.Handlers)
	}
}

func TestConfigFromFileMissingPathBubbles(t *testing.T) {
	// A non-default missing path should propagate the file error rather
	// than silently fall back to the embedded config.
	if _, err := configFromFile("/no/such/path/definitely-missing.yaml"); err == nil {
		t.Error("expected error for non-default missing config path")
	}
}

func TestConfigFromFileDefaultPathFallsBackToEmbedded(t *testing.T) {
	// Run from a clean tempdir so the default file doesn't exist; the
	// loader should then fall back to the embedded config.
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	cf, err := configFromFile(ConfigFileName)
	if err != nil {
		t.Fatalf("configFromFile err: %v", err)
	}
	if cf == nil {
		t.Fatal("config should not be nil")
	}
}
