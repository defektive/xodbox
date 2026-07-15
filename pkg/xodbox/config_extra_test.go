package xodbox

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestToConfigDefaultsFallback(t *testing.T) {
	// nil Defaults should populate canonical defaults.
	cf := &ConfigFile{}
	got := ToConfig(cf)

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
	got := ToConfig(cf)
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
	got := ToConfig(cf)
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

	cf, err := ConfigFromFile(path)
	if err != nil {
		t.Fatalf("ConfigFromFile err: %v", err)
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
	if _, err := ConfigFromFile("/no/such/path/definitely-missing.yaml"); err == nil {
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

	cf, err := ConfigFromFile(ConfigFileName)
	if err != nil {
		t.Fatalf("ConfigFromFile err: %v", err)
	}
	if cf == nil {
		t.Fatal("config should not be nil")
	}
}

func TestValidHandlerNames(t *testing.T) {
	names := ValidHandlerNames()
	want := []string{"DNS", "FTP", "HTTPX", "SMB", "SMTP", "SSH", "TCP"}
	if !slices.Equal(names, want) {
		t.Errorf("ValidHandlerNames() = %v, want %v", names, want)
	}
}

func TestValidNotifierNames(t *testing.T) {
	names := ValidNotifierNames()
	want := []string{"app_log", "discord", "slack", "webhook"}
	if !slices.Equal(names, want) {
		t.Errorf("ValidNotifierNames() = %v, want %v", names, want)
	}
}

func TestValidWorkerNames(t *testing.T) {
	names := ValidWorkerNames()
	want := []string{"purge"}
	if !slices.Equal(names, want) {
		t.Errorf("ValidWorkerNames() = %v, want %v", names, want)
	}
}

func TestValidateConfigFileValid(t *testing.T) {
	cf := &ConfigFile{
		Defaults: map[string]string{"server_name": "test"},
		Handlers: []map[string]string{
			{"handler": "TCP", "listener": ":0"},
		},
		Notifiers: []map[string]string{
			{"notifier": "app_log"},
		},
		Workers: []map[string]string{
			{"worker": "purge", "schedule": "@daily"},
		},
	}
	if errs := ValidateConfigFile(cf); len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestValidateConfigFileInvalid(t *testing.T) {
	cf := &ConfigFile{
		Handlers: []map[string]string{
			{"handler": "NOPE"},
			{"listener": ":0"},
		},
		Notifiers: []map[string]string{
			{"notifier": "fake"},
		},
		Workers: []map[string]string{
			{"worker": "gone"},
		},
	}
	errs := ValidateConfigFile(cf)
	if len(errs) != 4 {
		t.Errorf("expected 4 errors, got %d: %v", len(errs), errs)
	}
}

func TestWriteConfigFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.yaml")

	cf := &ConfigFile{
		Defaults: map[string]string{"server_name": "RT"},
		Handlers: []map[string]string{
			{"handler": "TCP", "listener": ":9999"},
		},
		Notifiers: []map[string]string{
			{"notifier": "app_log"},
		},
	}

	if err := WriteConfigFile(p, cf); err != nil {
		t.Fatalf("WriteConfigFile: %v", err)
	}

	got, err := ConfigFromFile(p)
	if err != nil {
		t.Fatalf("ConfigFromFile: %v", err)
	}

	if got.Defaults["server_name"] != "RT" {
		t.Errorf("server_name = %q, want RT", got.Defaults["server_name"])
	}
	if len(got.Handlers) != 1 || got.Handlers[0]["handler"] != "TCP" {
		t.Errorf("Handlers = %v, want one TCP entry", got.Handlers)
	}
	if len(got.Notifiers) != 1 || got.Notifiers[0]["notifier"] != "app_log" {
		t.Errorf("Notifiers = %v, want one app_log entry", got.Notifiers)
	}
}
