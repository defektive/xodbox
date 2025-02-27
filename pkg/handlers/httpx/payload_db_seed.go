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
			lg().Error("failed to seed", "tx.Error", tx.Error, "type", payload.Type, "pattern", payload.Pattern)
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

		newPayloads = append(newPayloads, getPayloadsFromFrontmatter(f)...)
	}

	return newPayloads
}

func getPayloadsFromFrontmatter(f io.Reader) []*Payload {
	var seedData = matter{}
	if _, err := frontmatter.Parse(f, &seedData); err != nil {
		lg().Error("failed to get front matter from:", "reader", f)
		panic(err)
	}

	return seedData.ToHTTPPayloads()
}

type matter struct {
	Title       string         `yaml:"title"`
	Description string         `yaml:"description"`
	Payloads    []*SeedPayload `yaml:"payloads"`
}

func (m matter) ToHTTPPayloads() []*Payload {
	var httpPayloads []*Payload
	for _, p := range m.Payloads {
		httpPayloads = append(httpPayloads, p.ToHTTPPayload())
	}

	return httpPayloads
}

type SeedPayload struct {
	Type             string       `yaml:"type"`
	SortOrder        int          `yaml:"sort_order"`
	Pattern          string       `yaml:"pattern"`
	InternalFunction string       `yaml:"internal_function"`
	IsFinal          bool         `yaml:"is_final"`
	Data             *PayloadData `yaml:"data"`
}

func (s *SeedPayload) ToHTTPPayload() *Payload {
	n := NewHTTPPayload()
	n.Project = model.DefaultProject()
	n.Pattern = s.Pattern
	n.SortOrder = s.SortOrder
	n.IsFinal = s.IsFinal

	if s.InternalFunction != "" {
		n.InternalFunction = s.InternalFunction
	}

	if s.Data != nil {
		n.Data = *s.Data
	}

	return n
}
