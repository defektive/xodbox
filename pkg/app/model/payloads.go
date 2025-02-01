package model

import (
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"os"
	"regexp"
	"time"
)

type Project struct {
	gorm.Model

	Name    string `gorm:"unique"`
	Code    string `gorm:"unique"`
	Default bool   `gorm:"default:false"`
}

//type Base64Data []byte
//
//func (pk Base64Data) MarshalYAML() (interface{}, error) {
//	return base64.StdEncoding.EncodeToString(pk), nil
//}
//
//func (pk *Base64Data) UnmarshalYAML(node *yaml.Node) error {
//	value := node.Value
//	ba, err := base64.StdEncoding.DecodeString(value)
//	if err != nil {
//		return err
//	}
//	*pk = ba
//	return nil
//}

type Payload struct {
	gorm.Model

	Type      string  `json:"type" gorm:"uniqueIndex:idx_type_pattern"`
	ProjectID uint    `json:"project_id"`
	Project   Project `json:"-" yaml:"-"`

	SortOrder int `json:"sort_order"`

	Pattern string `json:"pattern" gorm:"uniqueIndex:idx_type_pattern"`

	Data string `json:"data" yaml:"data" `

	patternRegexp *regexp.Regexp
}

func (p *Payload) PatternRegexp() *regexp.Regexp {
	if p.patternRegexp == nil {
		p.patternRegexp = regexp.MustCompile(p.Pattern)
	}

	return p.patternRegexp
}

type Interaction struct {
	gorm.Model

	PayloadID uint    `json:"payload_id"`
	Payload   Payload `json:"payload"`

	ProjectID uint    `json:"project_id"`
	Project   Project `json:"project"`

	RemoteAddr string `json:"remote_addr"`
	RemotePort string `json:"remote_port"`
	Data       []byte `json:"data"`
}

var db *gorm.DB

func DB() *gorm.DB {
	if db == nil {

		newLogger := logger.New(
			log.New(os.Stderr, "\r\n", log.LstdFlags), // io writer
			logger.Config{
				SlowThreshold:             time.Second,   // Slow SQL threshold
				LogLevel:                  logger.Silent, // Log level
				IgnoreRecordNotFoundError: true,          // Ignore ErrRecordNotFound error for logger
				ParameterizedQueries:      true,          // Don't include params in the SQL log
				Colorful:                  false,         // Disable color
			},
		)

		var err error
		db, err = gorm.Open(sqlite.Open("test.db"), &gorm.Config{
			Logger: newLogger,
		})
		if err != nil {
			panic("failed to connect database")
		}

		models := []interface{}{
			&Project{},
			&Payload{},
			&Interaction{},
		}

		err = db.AutoMigrate(models...)
		if err != nil {
			lg().Info("failed to migrate models", "error", err)
		}

		seed(db)

	}
	return db
}

var defaultProject = Project{
	Name:    "default",
	Code:    "",
	Default: true,
}

func seed(dbh *gorm.DB) {
	tx := dbh.FirstOrCreate(&defaultProject)
	if tx.Error != nil {
		lg().Info("failed to seed default project", "error", tx.Error)
	}
}

func DefaultProject() Project {
	return defaultProject
}

func SortedPayloads() []Payload {

	var payloads = []Payload{}

	db.Order("sort_order, project_id, pattern asc").Find(&payloads)

	return payloads
}
