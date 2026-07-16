package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/defektive/xodbox/pkg/xodbox"
	"github.com/spf13/cobra"
)

var configGetCmd = &cobra.Command{
	Use:   "get <path>",
	Short: "Get a config value by dot-notation path",
	Long:  `Query a specific value from the config file using a dot-notation path.`,
	Example: `  xodbox config get defaults.server_name
  xodbox config get handlers.0.listener
  xodbox config get notifiers.0.notifier`,
	Args: cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		cf, err := xodbox.ConfigFromFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}

		val, ok := getConfigValue(cf, args[0])
		if !ok {
			fmt.Fprintln(os.Stderr, "not set")
			os.Exit(1)
		}
		fmt.Println(val)
	},
}

func getConfigValue(cf *xodbox.ConfigFile, path string) (string, bool) {
	parts := strings.SplitN(path, ".", 2)
	if len(parts) == 0 {
		return "", false
	}

	section := parts[0]
	if len(parts) == 1 {
		return "", false
	}
	rest := parts[1]

	switch section {
	case "defaults":
		v, ok := cf.Defaults[rest]
		return v, ok

	case "handlers":
		return getMapSliceValue(cf.Handlers, rest)

	case "notifiers":
		return getMapSliceValue(cf.Notifiers, rest)

	case "workers":
		return getMapSliceValue(cf.Workers, rest)

	default:
		return "", false
	}
}

func getMapSliceValue(items []map[string]string, path string) (string, bool) {
	parts := strings.SplitN(path, ".", 2)
	idx, err := strconv.Atoi(parts[0])
	if err != nil || idx < 0 || idx >= len(items) {
		return "", false
	}
	if len(parts) == 1 {
		return "", false
	}
	v, ok := items[idx][parts[1]]
	return v, ok
}

func init() {
	configCmd.AddCommand(configGetCmd)
}
