package cmd

import (
	"fmt"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/spf13/cobra"
)

var sinkDescription string
var sinkNotify bool

var sinkCmd = &cobra.Command{
	Use:   "sink",
	Short: "Manage interaction sinks (named/described slugs).",
	Long: "Create and manage sinks: named, described slugs you embed in payloads " +
		"to correlate out-of-band interactions. View a sink's hits in the admin web UI.",
}

var sinkAddCmd = &cobra.Command{
	Use:   "add [slug]",
	Short: "Create a sink; generates a random slug when none is given.",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		slug := ""
		if len(args) == 1 {
			slug = args[0]
		}
		s, err := model.CreateSink(slug, sinkDescription, sinkNotify)
		if err != nil {
			return err
		}
		// Only the slug goes to stdout so it is clean to capture in a script:
		// SLUG=$(xodbox sink add --description "..."). The human-readable
		// confirmation goes to stderr.
		fmt.Fprintln(cmd.OutOrStdout(), s.Slug)
		if s.Description != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "created sink %q: %s\n", s.Slug, s.Description)
		}
		return nil
	},
}

var sinkListCmd = &cobra.Command{
	Use:   "list",
	Short: "List sinks and their hit counts.",
	Run: func(cmd *cobra.Command, args []string) {
		sinks := model.ListSinks()
		if len(sinks) == 0 {
			fmt.Println("no sinks; create one with 'xodbox sink add [slug] --description \"...\"'")
			return
		}
		for _, s := range sinks {
			fmt.Printf("%s\t%d hits\t%s\n", s.Slug, model.SinkEventCount(s.Slug), s.Description)
		}
	},
}

var sinkRmCmd = &cobra.Command{
	Use:   "rm <slug>",
	Short: "Delete a sink (its captured interactions are left untouched).",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := model.SinkBySlug(args[0]); err != nil {
			return fmt.Errorf("sink %q not found", args[0])
		}
		if err := model.DeleteSink(args[0]); err != nil {
			return err
		}
		fmt.Printf("deleted sink %q\n", args[0])
		return nil
	},
}

func init() {
	sinkAddCmd.Flags().StringVar(&sinkDescription, "description", "", "what this sink is for (shown in the UI and CLI list)")
	sinkAddCmd.Flags().BoolVar(&sinkNotify, "notify", false, "send notifications when this sink is hit")
	sinkCmd.AddCommand(sinkAddCmd, sinkListCmd, sinkRmCmd)
	XodboxCmd.AddCommand(sinkCmd)
}
