package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defektive/xodbox/pkg/types"
	"github.com/defektive/xodbox/pkg/xodbox"
	"github.com/spf13/cobra"
)

// cmdWorker is a minimal types.Worker for driving the CLI.
type cmdWorker struct {
	name     string
	schedule string
	err      error
	runs     int
}

func (w *cmdWorker) Name() string     { return w.name }
func (w *cmdWorker) Schedule() string { return w.schedule }
func (w *cmdWorker) Run(context.Context) error {
	w.runs++
	return w.err
}

// withWorkers points the package-level config at the given workers for the
// duration of a test. The CLI reads xdbxConfig, which PersistentPreRunE
// normally populates.
func withWorkers(t *testing.T, workers ...types.Worker) {
	t.Helper()
	saved := xdbxConfig
	savedFile := configFile
	t.Cleanup(func() {
		xdbxConfig = saved
		configFile = savedFile
	})
	configFile = "test.yaml"
	xdbxConfig = &xodbox.Config{Workers: workers}
}

// invoke calls a subcommand's handler directly with its output captured.
// Going through cobra's Execute() would re-run the root PersistentPreRunE,
// which reloads the config from disk and would clobber the workers under test.
func invoke(t *testing.T, cmd *cobra.Command, args []string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	t.Cleanup(func() {
		cmd.SetOut(nil)
		cmd.SetErr(nil)
	})

	var err error
	switch {
	case cmd.RunE != nil:
		err = cmd.RunE(cmd, args)
	case cmd.Run != nil:
		cmd.Run(cmd, args)
	default:
		t.Fatalf("command %q has no handler", cmd.Name())
	}
	return out.String(), err
}

func runList(t *testing.T) (string, error) {
	t.Helper()
	return invoke(t, workersListCmd, nil)
}

func runWorker(t *testing.T, name string) (string, error) {
	t.Helper()
	return invoke(t, workersRunCmd, []string{name})
}

func TestWorkersListShowsConfiguredJobs(t *testing.T) {
	withWorkers(t, &cmdWorker{name: "purge", schedule: "@daily"})

	out, err := runList(t)
	if err != nil {
		t.Fatalf("workers list: %v", err)
	}
	if !strings.Contains(out, "purge") || !strings.Contains(out, "@daily") {
		t.Errorf("output missing worker or schedule:\n%s", out)
	}
}

// The empty case is the one that matters: it is the answer to "why did my
// background job never run?".
func TestWorkersListEmptyExplainsWhy(t *testing.T) {
	withWorkers(t)

	out, err := runList(t)
	if err != nil {
		t.Fatalf("workers list: %v", err)
	}
	if !strings.Contains(out, "no workers configured") {
		t.Errorf("empty list should say no workers are configured; got:\n%s", out)
	}
	if !strings.Contains(out, "test.yaml") {
		t.Errorf("empty list should name the config file; got:\n%s", out)
	}
}

func TestWorkersRunExecutesTheWorker(t *testing.T) {
	w := &cmdWorker{name: "purge", schedule: "@daily"}
	withWorkers(t, w)

	out, err := runWorker(t, "purge")
	if err != nil {
		t.Fatalf("workers run: %v", err)
	}
	if w.runs != 1 {
		t.Errorf("worker ran %d times, want 1", w.runs)
	}
	if !strings.Contains(out, "completed") {
		t.Errorf("output should confirm completion; got:\n%s", out)
	}
}

func TestWorkersRunUnknownName(t *testing.T) {
	w := &cmdWorker{name: "purge", schedule: "@daily"}
	withWorkers(t, w)

	_, err := runWorker(t, "nope")
	if err == nil {
		t.Fatal("running an unknown worker should error")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error should name the missing worker; got %v", err)
	}
	if w.runs != 0 {
		t.Errorf("no worker should have run, got %d runs", w.runs)
	}
}

func TestWorkersRunPropagatesFailure(t *testing.T) {
	boom := errors.New("vacuum failed")
	withWorkers(t, &cmdWorker{name: "purge", schedule: "@daily", err: boom})

	_, err := runWorker(t, "purge")
	if err == nil {
		t.Fatal("a failing worker should surface an error")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error = %v, want it to wrap %v", err, boom)
	}
}
