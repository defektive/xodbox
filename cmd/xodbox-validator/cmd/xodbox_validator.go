package cmd

import (
	"github.com/spf13/cobra"
	"os"
)

var host = "localhost"

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "xodbox-validator",
	Short: "A vulnerable application validator for xodbox",
	Long:  `A vulnerable application validator for xodbox`,
	//Run: func(cmd *cobra.Command, args []string) {
	//
	//	//tests.XXE()
	//},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := RootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().StringVar(&host, "host", host, "Host")
}
