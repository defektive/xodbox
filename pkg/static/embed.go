package static

import (
	"embed"
	"io/fs"
)

//go:embed config
var embeddedFS embed.FS

func ReadDir(name string) ([]fs.DirEntry, error) {
	return embeddedFS.ReadDir(name)
}

func ReadFile(name string) ([]byte, error) {
	return embeddedFS.ReadFile(name)
}

func Open(name string) (fs.File, error) {
	return embeddedFS.Open(name)
}
