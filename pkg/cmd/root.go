package cmd

import (
	"github.com/defektive/xodbox/pkg/app"
	"github.com/defektive/xodbox/pkg/xlog"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var xodbox *app.Xodbox
var debug = false

// XodboxCmd represents the base command when called without any subcommands
var XodboxCmd = &cobra.Command{
	Use:   "xodbox",
	Short: "A network interaction listening post",
	Long:  `A network interaction listening post`,
	// Uncomment the following line if your bare application
	// has an action associated with it:

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if debug {
			xlog.LogLevel(slog.LevelDebug)
		}
		lg().Debug("debug mode", "debug", debug)
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := XodboxCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	XodboxCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Debug mode")
}
