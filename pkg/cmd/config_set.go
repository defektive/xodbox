package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/defektive/xodbox/pkg/xodbox"
	"github.com/spf13/cobra"
)

var configSetCmd = &cobra.Command{
	Use:   "set <path> <value>",
	Short: "Set a config value by dot-notation path",
	Long: `Set a specific value in the config file and save it. The config is
validated before writing; invalid configs are rejected.

Send SIGHUP to the running xodbox process to reload without a full restart.`,
	Example: `  xodbox config set defaults.server_name MyServer
  xodbox config set handlers.0.listener :8080
  xodbox config set notifiers.0.filter "^HTTP"`,
	Args: cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		cf, err := xodbox.ConfigFromFile(configFile)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		if err := setConfigValue(cf, args[0], args[1]); err != nil {
			return err
		}

		if errs := xodbox.ValidateConfigFile(cf); len(errs) > 0 {
			fmt.Fprintln(os.Stderr, "Validation errors:")
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "  - %s\n", e)
			}
			return fmt.Errorf("config is invalid, not saved")
		}

		if err := xodbox.WriteConfigFile(configFile, cf); err != nil {
			return fmt.Errorf("writing config: %w", err)
		}

		fmt.Printf("Set %s = %s\n", args[0], args[1])
		fmt.Println("Send SIGHUP to the running xodbox process to reload, or restart it.")
		return nil
	},
}

func setConfigValue(cf *xodbox.ConfigFile, path, value string) error {
	parts := strings.SplitN(path, ".", 2)
	if len(parts) < 2 {
		return fmt.Errorf("invalid path %q: expected section.key or section.index.key", path)
	}

	section := parts[0]
	rest := parts[1]

	switch section {
	case "defaults":
		if cf.Defaults == nil {
			cf.Defaults = map[string]string{}
		}
		cf.Defaults[rest] = value
		return nil

	case "handlers":
		return setMapSliceValue(&cf.Handlers, rest, value)

	case "notifiers":
		return setMapSliceValue(&cf.Notifiers, rest, value)

	case "workers":
		return setMapSliceValue(&cf.Workers, rest, value)

	default:
		return fmt.Errorf("unknown section %q (use defaults, handlers, notifiers, or workers)", section)
	}
}

func setMapSliceValue(items *[]map[string]string, path, value string) error {
	parts := strings.SplitN(path, ".", 2)
	if len(parts) < 2 {
		return fmt.Errorf("invalid path: expected index.key (e.g. 0.listener)")
	}
	idx, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("invalid index %q: %w", parts[0], err)
	}
	if idx < 0 || idx >= len(*items) {
		return fmt.Errorf("index %d out of range (have %d entries)", idx, len(*items))
	}
	(*items)[idx][parts[1]] = value
	return nil
}

func init() {
	configCmd.AddCommand(configSetCmd)
}
