package cmd

import (
	"fmt"
	"github.com/defektive/xodbox/pkg/xodbox"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"path"
)

// configCmd represents the base command when called without any subcommands
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "generate/print config",
	Long:  `generate/print config`,
	// Uncomment the following line if your bare application
	// has an action associated with it:

	Run: func(cmd *cobra.Command, args []string) {
		embedded, _ := cmd.Flags().GetBool("embedded")

		var bytes []byte
		var err error
		if embedded {
			bytes, err = xodbox.EmbeddedConfigReadFile(path.Join("config", xodbox.ConfigFileName))
		} else {
			bytes, err = yaml.Marshal(xdbxConfig)
		}
		if err != nil {
			panic(err)
		}
		fmt.Println(string(bytes))
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
	configCmd.Flags().BoolP("embedded", "e", false, "Print the embedded config file")
	//startCmd.Flags().BoolP("log", "l", false, "Print a log of interaction events")
	XodboxCmd.AddCommand(configCmd)
}
