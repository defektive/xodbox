package cmd

import (
	"github.com/defektive/xodbox/pkg/app"
	"github.com/defektive/xodbox/pkg/xlog"
	"github.com/spf13/cobra"
	"log/slog"
)

var configFile string
var appConfig *app.AppConfig
var xodbox *app.Xodbox
var debug = false

// XodboxCmd represents the base command when called without any subcommands
var XodboxCmd = &cobra.Command{
	Use:   "xodbox",
	Short: "A network interaction listening post",
	Long: `A network interaction listening post.

- Quickly determine if an application interacts with network services.
- Easily create custom responses to interaction requests.
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if debug {
			xlog.LogLevel(slog.LevelDebug)
		}
		lg().Debug("debug mode", "debug", debug)
		appConfig = app.LoadAppConfig(configFile)
		return nil
	},
}

func init() {
	XodboxCmd.PersistentFlags().StringVar(&configFile, "config", app.ConfigFileName, "Debug mode")
	XodboxCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Debug mode")
}
