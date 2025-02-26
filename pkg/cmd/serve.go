package cmd

import (
	"github.com/defektive/xodbox/pkg/xodbox"
	"github.com/spf13/cobra"
)

// serveCmd represents the base command when called without any subcommands
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start xodbox server.",
	Long:  `Start xodbox server.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:

	Run: func(cmd *cobra.Command, args []string) {
		xdbx = xodbox.NewApp(xdbxConfig)

		xdbx.Run()
	},
}

func init() {
	//startCmd.Flags().String("slack-webhook", "", "Slack Webhook URL")
	//startCmd.Flags().String("slack-user", "Pirate Virus", "Slack user")
	//startCmd.Flags().String("slack-channel", "", "Slack channel")
	//startCmd.Flags().String("slack-avatar", "", "Slack avatar emoji")
	//
	//startCmd.Flags().String("discord-webhook", "", "Discord webhook URL")
	//startCmd.Flags().String("discord-user", "Pirate Virus", "Discord user")
	//startCmd.Flags().String("discord-avatar", "", "Discord avatar URL")
	//startCmd.Flags().BoolP("log", "l", false, "Print a log of interaction events")
	//startCmd.Flags().BoolP("log", "l", false, "Print a log of interaction events")
	XodboxCmd.AddCommand(serveCmd)
}
