package main

import (
	"github.com/analog-substance/util/cli/build_info"
	"github.com/analog-substance/util/cli/completion"
	"github.com/analog-substance/util/cli/docs"
	"github.com/analog-substance/util/cli/glamour_help"
	"github.com/analog-substance/util/cli/updater/cobra_updater"
	"github.com/defektive/xodbox/pkg/cmd"
	"log"
	"os"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
)

var version = "v0.0.0"
var commit = "replace"

func main() {
	versionInfo := build_info.GetVersion(version, commit)
	app := pocketbase.New()

	app.RootCmd.Version = versionInfo.String()
	cobra_updater.AddToRootCmd(app.RootCmd, versionInfo)
	completion.AddToRootCmd(app.RootCmd)
	app.RootCmd.AddCommand(docs.CobraDocsCmd)
	glamour_help.AddToRootCmd(app.RootCmd)

	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		// serves static files from the provided public dir (if exists)
		se.Router.GET("/{path...}", apis.Static(os.DirFS("./pb_public"), false))

		return se.Next()
	})

	app.RootCmd.AddCommand(cmd.ConfigCmd)

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}

//
//// article.go
//package main
//
//import (
//"github.com/pocketbase/pocketbase/core"
//"github.com/pocketbase/pocketbase/tools/types"
//)
//
//// ensures that the Article struct satisfy the core.RecordProxy interface
//var _ core.RecordProxy = (*Article)(nil)
//
//type Article struct {
//	core.BaseRecordProxy
//}
//
//func (a *Article) Title() string {
//	return a.GetString("title")
//}
//
//func (a *Article) SetTitle(title string) {
//	a.Set("title", title)
//}
//
//func (a *Article) Slug() string {
//	return a.GetString("slug")
//}
//
//func (a *Article) SetSlug(slug string) {
//	a.Set("slug", slug)
//}
//
//func (a *Article) Created() types.DateTime {
//	return a.GetDateTime("created")
//}
//
//func (a *Article) Updated() types.DateTime {
//	return a.GetDateTime("updated")
//}
