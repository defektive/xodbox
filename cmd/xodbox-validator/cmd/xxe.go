package cmd

import (
	"github.com/spf13/cobra"
)

// xxeCmd represents the base command when called without any subcommands
var xxeCmd = &cobra.Command{
	Use:   "xxe",
	Short: "Test xxe actually exploits things",
	Long: `Test xxe actually exploits things

Do not run on untrusted things
`,
	Run: func(cmd *cobra.Command, args []string) {
		//tests.XXE()
	},
}

func init() {
	RootCmd.AddCommand(xxeCmd)
}
