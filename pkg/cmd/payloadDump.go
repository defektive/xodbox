package cmd

import (
	"fmt"
	"github.com/defektive/xodbox/pkg/app"
	"github.com/defektive/xodbox/pkg/app/model"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// PayloadDumpCmd represents the base command when called without any subcommands
var PayloadDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "dump payloads.",
	Long:  `dump payloads.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:

	Run: func(cmd *cobra.Command, args []string) {
		appConfig := app.LoadAppConfig("xodbox.yaml")
		xodbox = app.NewXodbox(appConfig)

		payloads := model.SortedPayloads()

		yamlBytes, err := yaml.Marshal(payloads)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(yamlBytes))

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
	PayloadCmd.AddCommand(PayloadDumpCmd)
}
