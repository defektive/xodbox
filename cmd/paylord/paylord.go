package main

import (
	"github.com/analog-substance/util/cli/build_info"
	"github.com/analog-substance/util/cli/completion"
	"github.com/analog-substance/util/cli/docs"
	"github.com/analog-substance/util/cli/glamour_help"
	"github.com/analog-substance/util/cli/updater/cobra_updater"
	"github.com/defektive/xodbox/cmd/paylord/cmd"
)

var version = "v0.0.0"
var commit = "replace"

func main() {
	versionInfo := build_info.GetVersion(version, commit)
	cmd.RootCmd.Version = versionInfo.String()
	cobra_updater.AddToRootCmd(cmd.RootCmd, versionInfo)
	completion.AddToRootCmd(cmd.RootCmd)
	cmd.RootCmd.AddCommand(docs.CobraDocsCmd)
	glamour_help.AddToRootCmd(cmd.RootCmd)

	cmd.Execute()
}
