package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// ConfigCmd represents the base command when called without any subcommands
var ConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "generate/print config",
	Long:  `generate/print config`,
	// Uncomment the following line if your bare application
	// has an action associated with it:

	Run: func(cmd *cobra.Command, args []string) {
		bytes, err := yaml.Marshal(appConfig)

		if err != nil {
			panic(err)
		}

		fmt.Println(string(bytes))
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
}
