package cmd

import (
	"github.com/defektive/xodbox/pkg/app"
	"github.com/spf13/cobra"
)

// StartCmd represents the base command when called without any subcommands
var StartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start xodbox server.",
	Long:  `Start xodbox server.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:

	Run: func(cmd *cobra.Command, args []string) {
		xodbox = app.NewXodbox(appConfig)

		xodbox.Run()
	},
}

func init() {
	//StartCmd.Flags().String("slack-webhook", "", "Slack Webhook URL")
	//StartCmd.Flags().String("slack-user", "Pirate Virus", "Slack user")
	//StartCmd.Flags().String("slack-channel", "", "Slack channel")
	//StartCmd.Flags().String("slack-avatar", "", "Slack avatar emoji")
	//
	//StartCmd.Flags().String("discord-webhook", "", "Discord webhook URL")
	//StartCmd.Flags().String("discord-user", "Pirate Virus", "Discord user")
	//StartCmd.Flags().String("discord-avatar", "", "Discord avatar URL")
	//StartCmd.Flags().BoolP("log", "l", false, "Print a log of interaction events")
	//StartCmd.Flags().BoolP("log", "l", false, "Print a log of interaction events")
	XodboxCmd.AddCommand(StartCmd)
}
