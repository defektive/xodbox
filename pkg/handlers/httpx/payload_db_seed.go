package httpx

import (
	"embed"
	"github.com/adrg/frontmatter"
	"github.com/defektive/xodbox/pkg/app/model"
	"gorm.io/gorm"
	"io/fs"
)

const InternalFnInspect = "inspect"

func getAllFilenames(efs *embed.FS) (files []string, err error) {
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

func getSeedsFromFiles() []*Payload {

	embeddedFiles, err := getAllFilenames(&embeddedSeedFS)
	if err != nil {
		panic(err)
	}

	seedPayloads := []*Payload{}

	for _, embeddedFile := range embeddedFiles {
		f, err := embeddedSeedFS.Open(embeddedFile)
		if err != nil {
			panic(err)
		}

		var seedData = matter{}
		if _, err := frontmatter.Parse(f, &seedData); err != nil {
			lg().Error("failed to get front matter from:", "embeddedFile", embeddedFile)
			panic(err)
		}

		for _, payload := range seedData.Payloads {

			lg().Debug("found seed", "file", embeddedFile, "pattern", payload.Pattern, "isfinal", payload.IsFinal)
		}
		seedPayloads = append(seedPayloads, seedData.ToHTTPPayloads()...)
	}

	return seedPayloads
}

var seeded = false

func Seed(dbh *gorm.DB) {
	if !seeded {
		seeded = true
		seedPayloads := getSeedsFromFiles()
		for _, seedPayload := range seedPayloads {
			seedPayload.Project = model.DefaultProject()
			tx := dbh.Create(seedPayload)
			if tx.Error != nil {
				lg().Error("failed to seed", tx.Error, "type", seedPayload.Type, "pattern", seedPayload.Pattern)
			}
		}
	}
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
