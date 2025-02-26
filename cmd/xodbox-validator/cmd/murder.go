package cmd

import (
	"github.com/defektive/xodbox/cmd/xodbox-validator/load"
	"github.com/spf13/cobra"
)

// MurderCmd represents the base command when called without any subcommands
var MurderCmd = &cobra.Command{
	Use:   "murder",
	Short: "A vulnerable application validator for xodbox",
	Long:  `A vulnerable application validator for xodbox`,
	Run: func(cmd *cobra.Command, args []string) {

		load.Murder()
	},
}

func init() {
	RootCmd.AddCommand(MurderCmd)
}
