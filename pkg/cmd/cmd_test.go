package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestXodboxCmdMetadata(t *testing.T) {
	if XodboxCmd.Use != "xodbox" {
		t.Errorf("Use = %q, want %q", XodboxCmd.Use, "xodbox")
	}
	if XodboxCmd.Short == "" {
		t.Error("Short description should be set")
	}
	if !strings.Contains(XodboxCmd.Long, "listening post") {
		t.Errorf("Long description missing 'listening post': %q", XodboxCmd.Long)
	}
}

func TestPersistentFlagsRegistered(t *testing.T) {
	for _, name := range []string{"config", "reset-db", "debug"} {
		if f := XodboxCmd.PersistentFlags().Lookup(name); f == nil {
			t.Errorf("persistent flag %q not registered", name)
		}
	}
}

func TestSubcommandsRegistered(t *testing.T) {
	want := map[string]bool{
		"serve":   false,
		"config":  false,
		"payload": false,
	}

	for _, c := range XodboxCmd.Commands() {
		// Use[0]-of-name handles "use [args...]" Use strings.
		name := strings.SplitN(c.Use, " ", 2)[0]
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}

	for name, found := range want {
		if !found {
			t.Errorf("subcommand %q not registered on XodboxCmd", name)
		}
	}
}

func TestPayloadDumpRegisteredUnderPayload(t *testing.T) {
	var payload *cobra.Command
	for _, c := range XodboxCmd.Commands() {
		if strings.SplitN(c.Use, " ", 2)[0] == "payload" {
			payload = c
			break
		}
	}
	if payload == nil {
		t.Fatal("payload command not found")
	}

	var foundDump bool
	for _, c := range payload.Commands() {
		if strings.SplitN(c.Use, " ", 2)[0] == "dump" {
			foundDump = true
			break
		}
	}
	if !foundDump {
		t.Error("dump command not registered under payload")
	}
}

func TestConfigCmdHasEmbeddedFlag(t *testing.T) {
	var config *cobra.Command
	for _, c := range XodboxCmd.Commands() {
		if strings.SplitN(c.Use, " ", 2)[0] == "config" {
			config = c
			break
		}
	}
	if config == nil {
		t.Fatal("config command not found")
	}
	if f := config.Flags().Lookup("embedded"); f == nil {
		t.Error("config command should have --embedded flag")
	}
	if f := config.Flags().ShorthandLookup("e"); f == nil {
		t.Error("config command should have -e shorthand")
	}
}
