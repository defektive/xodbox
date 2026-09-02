package cmd

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/defektive/xodbox/pkg/types"
	"github.com/spf13/cobra"
)

var workersCmd = &cobra.Command{
	Use:   "workers",
	Short: "Inspect and run background jobs.",
	Long: "Background jobs (workers) normally run on the schedule set under the " +
		"'workers:' key in the config file. These subcommands let you see what is " +
		"configured and run a job immediately, without waiting for its next tick.",
}

var workersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the background jobs configured in the config file.",
	Long: "Print each worker in the config file with its schedule. An empty list " +
		"means no 'workers:' key is configured, so no background job will ever run.",
	Example: "  xodbox workers list",
	Run: func(cmd *cobra.Command, args []string) {
		workers := xdbxConfig.Workers
		if len(workers) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(),
				"no workers configured; add a 'workers:' block to "+configFile+
					" (see 'xodbox config -e')")
			return
		}

		tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tSCHEDULE")
		for _, w := range workers {
			fmt.Fprintf(tw, "%s\t%s\n", w.Name(), w.Schedule())
		}
		_ = tw.Flush()
	},
}

var workersRunCmd = &cobra.Command{
	Use:   "run [name]",
	Short: "Run a background job once, immediately.",
	Long: "Run a configured worker once in the foreground and wait for it to " +
		"finish, then exit. Useful for applying a retention policy on demand or " +
		"for checking that a job does what you expect before trusting it to a " +
		"schedule.\n\n" +
		"This opens its own connection to the database. If 'xodbox serve' is " +
		"running against the same file, a job that writes heavily -- the purge " +
		"worker's VACUUM in particular -- can block or fail on SQLite's write " +
		"lock. Prefer the admin console's Run now button, which runs the job " +
		"inside the live server, or stop the server first.\n\n" +
		"Interrupt with Ctrl-C to cancel the run's context; the worker decides " +
		"how quickly it can stop.",
	Example: "  xodbox workers run purge",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		var target types.Worker
		for _, w := range xdbxConfig.Workers {
			if w.Name() == name {
				target = w
				break
			}
		}
		if target == nil {
			return fmt.Errorf("no worker named %q is configured in %s (see 'xodbox workers list')", name, configFile)
		}

		// Ctrl-C cancels the run's context rather than killing the process
		// mid-write, matching how the scheduler shuts a worker down.
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()

		fmt.Fprintf(cmd.ErrOrStderr(), "running worker %q...\n", name)
		start := time.Now()
		if err := target.Run(ctx); err != nil {
			return fmt.Errorf("worker %q failed after %s: %w", name, time.Since(start).Round(time.Millisecond), err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "worker %q completed in %s\n", name, time.Since(start).Round(time.Millisecond))
		return nil
	},
}

func init() {
	workersCmd.AddCommand(workersListCmd)
	workersCmd.AddCommand(workersRunCmd)
	XodboxCmd.AddCommand(workersCmd)
}
