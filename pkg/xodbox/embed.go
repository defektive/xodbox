package xodbox

import (
	"embed"
	"io/fs"
)

//go:embed config
var EmbeddedConfig embed.FS

func ReadDir(name string) ([]fs.DirEntry, error) {
	return EmbeddedConfig.ReadDir(name)
}

func EmbeddedConfigReadFile(name string) ([]byte, error) {
	return EmbeddedConfig.ReadFile(name)
}

func Open(name string) (fs.File, error) {
	return EmbeddedConfig.Open(name)
}
