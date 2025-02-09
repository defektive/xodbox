package main

import (
	"github.com/pocketbase/pocketbase/plugins/migratecmd"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
)

var managementHost = "localhost:8090"

func main() {
	//versionInfo := build_info.GetVersion(version, commit)
	app := pocketbase.New()

	// loosely check if it was executed using "go run"
	isGoRun := strings.HasPrefix(os.Args[0], os.TempDir())
	migratecmd.MustRegister(app, app.RootCmd, migratecmd.Config{
		// enable auto creation of migration files when making collection changes in the Dashboard
		// (the isGoRun check is to enable it only during development)
		Automigrate: isGoRun,
	})

	//app.RootCmd.Version = versionInfo.String()
	//cobra_updater.AddToRootCmd(app.RootCmd, versionInfo)
	//completion.AddToRootCmd(app.RootCmd)
	//app.RootCmd.AddCommand(docs.CobraDocsCmd)
	//glamour_help.AddToRootCmd(app.RootCmd)

	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		// serves static files from the provided public dir (if exists)
		se.Router.GET("/{path...}", apis.Static(os.DirFS("./pb_public"), false))
		return se.Next()
	})

	app.OnSettingsReload().BindFunc(func(e *core.SettingsReloadEvent) error {
		if err := e.Next(); err != nil {
			return err
		}

		parsed, err := url.Parse(e.App.Settings().Meta.AppURL)
		if err != nil {
			return nil
		}
		managementHost = parsed.Host

		return nil
	})

	app.OnBootstrap().BindFunc(func(e *core.BootstrapEvent) error {
		app.Logger().Info("i am a server: %s", e.App.Settings().Meta.AppURL)

		return e.Next()
	})

	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		// register a global middleware
		se.Router.BindFunc(func(e *core.RequestEvent) error {
			if e.Request.Host == managementHost {
				return e.Next()
			}

			// here we will hand off things to xodbox
			//
			//// not a mgmt host request
			//projects, err := GetProjects()
			//if err != nil {
			//	return err
			//}
			//
			//for _, project := range projects {
			//	if strings.Contains(e.Request.URL.Path, project.Id) {
			//
			//		collection, err := app.FindCollectionByNameOrId("hook_data")
			//		if err != nil {
			//			return err
			//		}
			//
			//		record := core.NewRecord(collection)
			//		record.Set("remote_addr", e.Request.RemoteAddr)
			//		record.Set("method", e.Request.Method)
			//		record.Set("path", e.Request.URL.Path)
			//		record.Set("project", project.Id)
			//
			//		app.Save(record)
			//
			//	}
			//}

			return e.BadRequestError("bad", "yep")
		})

		return se.Next()
	})

	//app.RootCmd.AddCommand(cmd.ConfigCmd)

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
