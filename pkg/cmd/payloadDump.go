package cmd

import (
	"fmt"
	"github.com/defektive/xodbox/pkg/app"
	"github.com/defektive/xodbox/pkg/app/model"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// payloadDumpCmd represents the base command when called without any subcommands
var payloadDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "dump payloads.",
	Long:  `dump payloads.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:

	Run: func(cmd *cobra.Command, args []string) {
		appConfig := app.LoadAppConfig("xodbox.yaml")
		xodbox = app.NewXodbox()

		for _, notifier := range appConfig.Notifiers {
			xodbox.RegisterNotificationHandler(notifier)
		}

		payloads := model.SortedPayloads()

		yamlBytes, err := yaml.Marshal(payloads)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(yamlBytes))

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
	payloadCmd.AddCommand(payloadDumpCmd)
}
