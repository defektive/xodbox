package httpx

import (
	"github.com/defektive/xodbox/pkg/model"
	"github.com/fsnotify/fsnotify"
	"gorm.io/gorm/clause"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var watcher *fsnotify.Watcher

func watchForChanges(dirToWatch string) {
	watcher, _ = fsnotify.NewWatcher()
	defer watcher.Close()

	if err := filepath.Walk(dirToWatch, watchDir); err != nil {
		lg().Error("error watching for changes", "err", err)
	}
	done := make(chan bool)
	dbncr := Debounce(1 * time.Second)

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				lg().Debug("watcher.Error", "event", event)

				modifiedFiles[event.Name] = true
				go dbncr(handleFileEvent)

			case err := <-watcher.Errors:
				lg().Error("watcher.Error", "err", err)
			}
		}
	}()

	<-done
}

var modifiedFiles = map[string]bool{}

func watchDir(path string, fi os.FileInfo, err error) error {
	if fi.Mode().IsDir() {
		return watcher.Add(path)
	}

	return nil
}

func handleFileEvent() {
	for modifiedFile := range modifiedFiles {
		delete(modifiedFiles, modifiedFile)
		f, err := os.Open(modifiedFile)
		if err != nil {
			lg().Error("error opening file", "file", modifiedFile, "err", err)
			continue
		}

		p, err := getPayloadsFromFrontmatter(f)
		if err != nil {
			lg().Error("error getting frontmatter", "file", modifiedFile, "err", err)
			continue
		}

		p.Project = model.DefaultProject()

		tx := model.DB().Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "name"}}, // key colume
			DoUpdates: clause.AssignmentColumns([]string{
				"description",
				"pattern",
				"is_final",
				"data",
				"sort_order",
				"internal_function",
			}), // column needed to be updated
		}).Create(&p)

		if tx.Error != nil {
			lg().Error("error creating payload", "err", tx.Error)
		} else {
			payloads = []*Payload{}
		}
	}
}

func Debounce(after time.Duration) func(f func()) {
	d := &debouncer{after: after}

	return func(f func()) {
		d.add(f)
	}
}

type debouncer struct {
	mu    sync.Mutex
	after time.Duration
	timer *time.Timer
}

func (d *debouncer) add(f func()) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil {
		d.timer.Stop()
	}
	d.timer = time.AfterFunc(d.after, f)
}
