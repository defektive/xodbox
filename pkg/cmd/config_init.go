package cmd

import (
	"fmt"
	"os"
	"path"

	"github.com/defektive/xodbox/pkg/xodbox"
	"github.com/spf13/cobra"
)

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Write the default config file to disk",
	Long:  `Write the embedded default config to the --config path (default xodbox.yaml). Refuses to overwrite unless --force is set.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		force, _ := cmd.Flags().GetBool("force")

		if !force {
			if _, err := os.Stat(configFile); err == nil {
				return fmt.Errorf("%s already exists (use --force to overwrite)", configFile)
			}
		}

		b, err := xodbox.EmbeddedConfigReadFile(path.Join("config", xodbox.ConfigFileName))
		if err != nil {
			return fmt.Errorf("reading embedded config: %w", err)
		}

		if err := os.WriteFile(configFile, b, 0o600); err != nil {
			return fmt.Errorf("writing config: %w", err)
		}

		fmt.Printf("Config written to %s\n", configFile)
		return nil
	},
}

func init() {
	configInitCmd.Flags().Bool("force", false, "Overwrite existing config file")
	configCmd.AddCommand(configInitCmd)
}
