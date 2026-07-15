package cmd

import (
	"fmt"
	"os"

	"github.com/defektive/xodbox/pkg/xodbox"
	"github.com/spf13/cobra"
)

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate the config file",
	Long:  `Load the config file and check that all handler, notifier, and worker names are valid.`,
	Run: func(_ *cobra.Command, _ []string) {
		cf, err := xodbox.ConfigFromFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}

		errs := xodbox.ValidateConfigFile(cf)
		if len(errs) == 0 {
			fmt.Println("Config is valid.")
			return
		}

		fmt.Fprintln(os.Stderr, "Config validation errors:")
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "  - %s\n", e)
		}
		os.Exit(1)
	},
}

func init() {
	configCmd.AddCommand(configValidateCmd)
}
