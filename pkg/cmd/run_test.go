package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/xodbox"
)

// captureStdout redirects os.Stdout for the duration of f and returns
// whatever f wrote there. fmt.Println in the command Run funcs writes
// to os.Stdout, so this is the cleanest way to observe their output.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w

	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()

	defer func() {
		os.Stdout = orig
		_ = w.Close()
		<-done
		_ = r.Close()
	}()

	f()
	_ = w.Close()
	os.Stdout = orig
	<-done
	_ = r.Close()
	return buf.String()
}

func TestConfigCmdEmbeddedPrintsConfig(t *testing.T) {
	// Need configCmd to read the --embedded flag as true.
	if err := configCmd.Flags().Set("embedded", "true"); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	t.Cleanup(func() { _ = configCmd.Flags().Set("embedded", "false") })

	out := captureStdout(t, func() {
		configCmd.Run(configCmd, nil)
	})

	if out == "" {
		t.Fatal("expected non-empty stdout from --embedded config dump")
	}
	if !strings.Contains(out, "handlers") {
		t.Errorf("embedded config should reference 'handlers', got first 200 chars: %q",
			out[:min(len(out), 200)])
	}
}

func TestConfigCmdNonEmbeddedDumpsLoadedYAML(t *testing.T) {
	// Seed the package-level xdbxConfig with something deterministic
	// and tell configCmd to render it (default Embedded=false).
	saved := xdbxConfig
	t.Cleanup(func() { xdbxConfig = saved })

	xdbxConfig = &xodbox.Config{
		TemplateData: map[string]string{"hello": "world"},
	}

	if err := configCmd.Flags().Set("embedded", "false"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	out := captureStdout(t, func() {
		configCmd.Run(configCmd, nil)
	})

	if !strings.Contains(out, "hello") || !strings.Contains(out, "world") {
		t.Errorf("dumped YAML should include the template data, got: %q", out)
	}
}

func TestPayloadDumpRunsAgainstTempDB(t *testing.T) {
	// payloadDump.Run hard-codes xodbox.LoadConfig("xodbox.yaml") and
	// calls model.SortedPayloads() — drive it from a tempdir where the
	// config and DB are isolated so the test doesn't pollute the repo.
	dir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	// Point the model singleton at a tempdir DB and seed a payload.
	model.LoadDBWithOptions(model.DBOptions{Path: filepath.Join(dir, "test.db")})
	t.Cleanup(func() {})
	if err := model.DB().Create(&model.Payload{
		Name:    "from-dump-test",
		Pattern: "^/x$",
		Type:    "HTTPX",
	}).Error; err != nil {
		t.Fatalf("seed payload: %v", err)
	}

	out := captureStdout(t, func() {
		payloadDumpCmd.Run(payloadDumpCmd, nil)
	})

	if !strings.Contains(out, "from-dump-test") {
		t.Errorf("payload dump output should include seeded payload name; got first 400 chars:\n%s",
			out[:min(len(out), 400)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
