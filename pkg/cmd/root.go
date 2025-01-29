package cmd

import (
	"github.com/defektive/xodbox/pkg/app"
	"github.com/defektive/xodbox/pkg/xlog"
	"gopkg.in/yaml.v3"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var xodbox *app.Xodbox
var debug bool = false

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "xodbox",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if debug {
			xlog.LogLevel(slog.LevelDebug)
		}
		lg().Debug("debug mode", "debug", debug)
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		appConfig := app.LoadAppConfig("xodbox.yaml")
		xodbox = app.NewXodbox()

		for _, notifier := range appConfig.Notifiers {
			xodbox.RegisterNotificationHandler(notifier)
		}

		lg().Debug("run app with handlers", "handlers", appConfig.Handlers)
		xodbox.Run(appConfig.Handlers)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {

	rootCmd.Flags().String("slack-webhook", "", "Slack Webhook URL")
	rootCmd.Flags().String("slack-user", "Pirate Virus", "Slack user")
	rootCmd.Flags().String("slack-channel", "", "Slack channel")
	rootCmd.Flags().String("slack-avatar", "", "Slack avatar emoji")

	rootCmd.Flags().String("discord-webhook", "", "Discord webhook URL")
	rootCmd.Flags().String("discord-user", "Pirate Virus", "Discord user")
	rootCmd.Flags().String("discord-avatar", "", "Discord avatar URL")

	rootCmd.Flags().BoolP("log", "l", false, "Print a log of interaction events")

	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Debug mode")
}

func readConfig() (*app.ConfigFile, error) {
	b, err := os.ReadFile("xodbox.yaml")
	if err != nil {
		return nil, err
	}

	var conf *app.ConfigFile
	err = yaml.Unmarshal(b, conf)
	return conf, err
}
