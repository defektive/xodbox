package httpx

import (
	"github.com/adrg/frontmatter"
	"github.com/defektive/xodbox/pkg/model"
	"gorm.io/gorm"
	"io"
	"io/fs"
	"os"
)

const InternalFnInspect = "inspect"

var seeded = false

func Seed(dbh *gorm.DB) {
	if !seeded {
		seeded = true
		CreatePayloadsFromFS(&embeddedSeedFS, dbh)

	}
}

func CreatePayloadsFromDir(dir string, dbh *gorm.DB) {
	fsDir := os.DirFS(dir)
	newPayloads := getPayloadsFromFS(fsDir)
	CreatePayloads(newPayloads, dbh)
}

func CreatePayloadsFromFS(fsDir fs.FS, dbh *gorm.DB) {
	seedPayloads := getPayloadsFromFS(&embeddedSeedFS)
	CreatePayloads(seedPayloads, dbh)
}

func CreatePayloads(payloads []*Payload, dbh *gorm.DB) {
	for _, payload := range payloads {
		payload.Project = model.DefaultProject()
		tx := dbh.Create(payload)
		if tx.Error != nil {
			lg().Error("failed to create payload", "tx.Error", tx.Error, "name", payload.Name, "type", payload.Type, "pattern", payload.Pattern)
		}
	}
}

func getAllFilenames(efs fs.FS) (files []string, err error) {
	if err := fs.WalkDir(efs, ".", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}

		files = append(files, path)

		return nil
	}); err != nil {
		return nil, err
	}

	return files, nil
}

func getPayloadsFromFS(fsToCheck fs.FS) []*Payload {

	files, err := getAllFilenames(fsToCheck)
	if err != nil {
		panic(err)
	}

	newPayloads := []*Payload{}

	for _, nextFile := range files {
		f, err := fsToCheck.Open(nextFile)
		if err != nil {
			panic(err)
		}

		newPayloads = append(newPayloads, getPayloadsFromFrontmatter(f))
	}

	return newPayloads
}

func getPayloadsFromFrontmatter(f io.Reader) *Payload {
	var seedData = &SeedPayload{}
	if _, err := frontmatter.Parse(f, &seedData); err != nil {
		lg().Error("failed to get front matter from:", "reader", f)
		panic(err)
	}

	return seedData.ToHTTPPayload()
}

type SeedPayload struct {
	Title            string       `yaml:"title"`
	Description      string       `yaml:"description"`
	Weight           int          `yaml:"weight"`
	Pattern          string       `yaml:"pattern"`
	InternalFunction string       `yaml:"internal_function"`
	IsFinal          bool         `yaml:"is_final"`
	Data             *PayloadData `yaml:"data"`
}

func (s *SeedPayload) ToHTTPPayload() *Payload {
	n := NewHTTPPayload()
	n.Project = model.DefaultProject()
	n.Name = s.Title
	n.Description = s.Description
	n.Pattern = s.Pattern
	n.SortOrder = s.Weight
	n.IsFinal = s.IsFinal

	if s.InternalFunction != "" {
		n.InternalFunction = s.InternalFunction
	}

	if s.Data != nil {
		n.Data = *s.Data
	}

	return n
}
