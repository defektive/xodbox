package cmd

import (
	"fmt"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/spf13/cobra"
)

var (
	purgeRemotes []string
	purgeTarget  string
	purgeHandler string
	purgeDryRun  bool
)

var interactionsCmd = &cobra.Command{
	Use:   "interactions",
	Short: "Inspect and prune recorded interactions.",
	Long: "Manage the interactions the listeners have recorded. Use 'purge' to " +
		"remove noise from a known source (e.g. a leftover beacon from an old " +
		"test) that has been flooding the database.",
}

var interactionsPurgeCmd = &cobra.Command{
	Use:   "purge",
	Short: "Delete recorded interactions matching a source, target, or handler.",
	Long: "Delete interactions matching the given filters (ANDed together). At " +
		"least one filter is required so the whole table isn't wiped by mistake. " +
		"Pair this with the ignore_cidrs / ignore_pattern config defaults to stop " +
		"the same noisy callout from being recorded going forward.\n\n" +
		"Examples:\n" +
		"  xodbox interactions purge --remote 203.0.113.7\n" +
		"  xodbox interactions purge --remote 10.0.0.0/8 --dry-run\n" +
		"  xodbox interactions purge --target /old-test-callback --handler httpx",
	RunE: func(cmd *cobra.Command, args []string) error {
		f := model.InteractionPurgeFilter{
			Remotes: purgeRemotes,
			Target:  purgeTarget,
			Handler: purgeHandler,
		}

		if purgeDryRun {
			matched, err := model.MatchingInteractions(f)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "dry-run: %d interaction(s) match; nothing deleted\n", len(matched))
			return nil
		}

		n, err := model.PurgeInteractions(f)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "deleted %d interaction(s)\n", n)
		return nil
	},
}

func init() {
	interactionsPurgeCmd.Flags().StringSliceVar(&purgeRemotes, "remote", nil, "source IP or CIDR to purge (repeatable, comma-separated)")
	interactionsPurgeCmd.Flags().StringVar(&purgeTarget, "target", "", "substring matched against the request target (HTTP path / DNS qname)")
	interactionsPurgeCmd.Flags().StringVar(&purgeHandler, "handler", "", "restrict to a single handler (e.g. httpx, dns)")
	interactionsPurgeCmd.Flags().BoolVar(&purgeDryRun, "dry-run", false, "report how many rows match without deleting")
	interactionsCmd.AddCommand(interactionsPurgeCmd)
	XodboxCmd.AddCommand(interactionsCmd)
}
