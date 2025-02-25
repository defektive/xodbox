package httpx

import (
	"embed"
	"github.com/adrg/frontmatter"
	"github.com/defektive/xodbox/pkg/app/model"
	"gorm.io/gorm"
	"io/fs"
	"log"
)

const InternalFnInspect = "inspect"

//go:embed seeds
var embeddedFS embed.FS

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

func getSeedsFromFiles() []*HTTPPayload {

	embeddedFiles, err := getAllFilenames(&embeddedFS)
	if err != nil {
		panic(err)
	}

	seedPayloads := []*HTTPPayload{}

	for _, embeddedFile := range embeddedFiles {
		f, err := embeddedFS.Open(embeddedFile)
		if err != nil {
			panic(err)
		}

		var seedData = matter{}
		if _, err := frontmatter.Parse(f, &seedData); err != nil {
			log.Println("failed to get front matter from:", embeddedFile)
			panic(err)
		}

		seedPayloads = append(seedPayloads, seedData.ToHTTPPayloads()...)
	}

	return seedPayloads
}

func Seed(dbh *gorm.DB) {
	seedPayloads := getSeedsFromFiles()

	for _, seedPayload := range seedPayloads {
		seedPayload.Project = model.DefaultProject()
		tx := dbh.Create(seedPayload)
		if tx.Error != nil {
			lg().Error("failed to seed", tx.Error, "type", seedPayload.Type, "pattern", seedPayload.Pattern)
		}
	}
	return
}

func newDefaultPayload(pattern string, sortOrder int) *HTTPPayload {
	n := NewHTTPPayload()
	n.Project = model.DefaultProject()
	n.Pattern = pattern
	n.SortOrder = sortOrder
	return n
}

type matter struct {
	Title       string         `yaml:"title"`
	Description string         `yaml:"description"`
	Payloads    []*SeedPayload `yaml:"payloads"`
}

func (m matter) ToHTTPPayloads() []*HTTPPayload {
	httpPayloads := []*HTTPPayload{}
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
	Data             *PayloadData `json,yaml:"data"`
}

func (s *SeedPayload) ToHTTPPayload() *HTTPPayload {
	n := NewHTTPPayload()
	n.Project = model.DefaultProject()
	n.Pattern = s.Pattern
	n.SortOrder = s.SortOrder

	if s.InternalFunction != "" {
		n.InternalFunction = s.InternalFunction
	}

	if s.Data != nil {
		n.Data = *s.Data
	}

	return n
}

//
//type HeaderTemplate struct {
//	HeaderTemplate *template.Template
//	ValueTemplate  *template.Template
//}
//
//type PayloadData struct {
//	Headers         map[string]string `json:"headers"`
//	Body            string            `json:"body"`
//	headerTemplates []*HeaderTemplate
//	bodyTemplate    *template.Template
//}
