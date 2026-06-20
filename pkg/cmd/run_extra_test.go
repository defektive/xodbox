package cmd

import (
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/defektive/xodbox/pkg/xlog"
)

func TestLgReturnsLogger(t *testing.T) {
	if lg() == nil {
		t.Fatal("lg() returned nil")
	}
	// second call exercises the memoized branch
	if lg() == nil {
		t.Fatal("lg() returned nil on second call")
	}
}

// TestExecuteRunsConfigEmbedded drives the whole command tree through the
// exported Execute() entrypoint by way of os.Args. `config -e` only prints the
// embedded config (no network listener is bound), so this stays hermetic while
// exercising Execute(), PersistentPreRunE (LoadConfig falls back to the
// embedded config) and the config subcommand.
func TestExecuteRunsConfigEmbedded(t *testing.T) {
	savedArgs := os.Args
	t.Cleanup(func() {
		os.Args = savedArgs
		// reset the flag so other tests see the default value
		_ = configCmd.Flags().Set("embedded", "false")
	})
	os.Args = []string{"xodbox", "config", "-e"}

	out := captureStdout(t, func() {
		Execute()
	})

	if !strings.Contains(out, "handlers") {
		t.Errorf("Execute() config -e output should reference 'handlers'; got first 200 chars: %q",
			out[:min(len(out), 200)])
	}
}

// TestPersistentPreRunEDebugRaisesLogLevel exercises the debug branch of the
// root command's PersistentPreRunE, which flips the global log level to Debug.
func TestPersistentPreRunEDebugRaisesLogLevel(t *testing.T) {
	savedDebug := debug
	savedConfigFile := configFile
	savedConfig := xdbxConfig
	t.Cleanup(func() {
		debug = savedDebug
		configFile = savedConfigFile
		xdbxConfig = savedConfig
		xlog.LogLevel(slog.LevelInfo)
	})

	debug = true
	configFile = "" // empty path != ConfigFileName, so read a real temp file
	// write a minimal but valid config to a temp file so LoadConfig succeeds
	tmp := t.TempDir() + "/xodbox.yaml"
	if err := os.WriteFile(tmp, []byte("listeners: []\n"), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	configFile = tmp

	if err := XodboxCmd.PersistentPreRunE(XodboxCmd, nil); err != nil {
		t.Fatalf("PersistentPreRunE returned error: %v", err)
	}
	if xdbxConfig == nil {
		t.Error("PersistentPreRunE should have populated xdbxConfig")
	}
}
