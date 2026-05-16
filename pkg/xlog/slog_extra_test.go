package xlog

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestSetAppName(t *testing.T) {
	saved := appName
	t.Cleanup(func() { appName = saved })

	appName = ""
	SetAppName("myapp")
	if appName != "myapp" {
		t.Errorf("SetAppName did not set appName, got %q", appName)
	}
}

func TestGetAppNameFromPkg(t *testing.T) {
	saved := appName
	t.Cleanup(func() { appName = saved })

	appName = ""
	got := getAppName()
	if got != "xodbox" {
		t.Errorf("getAppName() = %q, want xodbox (last segment of app pkg)", got)
	}
	if appName != "xodbox" {
		t.Errorf("appName cache not populated, got %q", appName)
	}
}

func TestLoggerReturnsInstance(t *testing.T) {
	if Logger() == nil {
		t.Error("Logger() returned nil")
	}
}

func TestWithGroupAttachesPackage(t *testing.T) {
	saved := logger
	defer func() { logger = saved }()

	var buf bytes.Buffer
	logger = slog.New(slog.NewTextHandler(&buf, nil))

	g := WithGroup("some/pkg")
	g.Info("hello")

	out := buf.String()
	if !strings.Contains(out, "some/pkg") {
		t.Errorf("log output missing group package: %q", out)
	}
}

func TestWithGroupFromFn(t *testing.T) {
	saved := logger
	defer func() { logger = saved }()

	var buf bytes.Buffer
	logger = slog.New(slog.NewTextHandler(&buf, nil))

	g := WithGroupFromFn(TestWithGroupFromFn)
	g.Info("hi")

	if !strings.Contains(buf.String(), "pkg/xlog") {
		t.Errorf("log output should reference pkg/xlog, got %q", buf.String())
	}
}

func TestGetUsesCallerPkg(t *testing.T) {
	saved := logger
	defer func() { logger = saved }()

	var buf bytes.Buffer
	logger = slog.New(slog.NewTextHandler(&buf, nil))

	g := Get()
	g.Info("hi")

	if !strings.Contains(buf.String(), "pkg/xlog") {
		t.Errorf("Get() should attribute to caller's pkg, got %q", buf.String())
	}
}

func TestLogLevelChangesLeveling(t *testing.T) {
	saved := logger
	savedLevel := logLevel.Level()
	defer func() {
		logger = saved
		LogLevel(savedLevel)
	}()

	var buf bytes.Buffer
	logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: logLevel}))

	// At Info level, Debug should be suppressed.
	LogLevel(slog.LevelInfo)
	logger.Debug("hidden")
	if strings.Contains(buf.String(), "hidden") {
		t.Errorf("debug should be suppressed at Info level: %q", buf.String())
	}

	// At Debug level, Debug should pass through.
	buf.Reset()
	LogLevel(slog.LevelDebug)
	logger.Debug("shown")
	if !strings.Contains(buf.String(), "shown") {
		t.Errorf("debug should appear at Debug level: %q", buf.String())
	}
}

func TestRelPkg(t *testing.T) {
	got := relPkg(TestRelPkg)
	if got != "pkg/xlog" {
		t.Errorf("relPkg() = %q, want pkg/xlog", got)
	}
}

// ensure os.Stderr import is kept (the init handler writes there) — referenced
// here to discourage accidental removal during refactoring.
var _ = os.Stderr
