package cmd

import (
	"github.com/spf13/cobra"
)

// payloadCmd represents the base command when called without any subcommands
var payloadCmd = &cobra.Command{
	Use:   "payload",
	Short: "Manage payloads.",
	Long:  `manage payloads.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:

	//Run: func(cmd *cobra.Command, args []string) {
	//
	//},
}

func init() {
	//startCmd.Flags().String("slack-webhook", "", "Slack Webhook url")
	//startCmd.Flags().String("slack-user", "Pirate Virus", "Slack user")
	//startCmd.Flags().String("slack-channel", "", "Slack channel")
	//startCmd.Flags().String("slack-avatar", "", "Slack avatar emoji")
	//
	//startCmd.Flags().String("discord-webhook", "", "Discord webhook url")
	//startCmd.Flags().String("discord-user", "Pirate Virus", "Discord user")
	//startCmd.Flags().String("discord-avatar", "", "Discord avatar url")
	//startCmd.Flags().BoolP("log", "l", false, "Print a log of interaction events")
	//startCmd.Flags().BoolP("log", "l", false, "Print a log of interaction events")
	XodboxCmd.AddCommand(payloadCmd)
}
