package model

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Project struct {
	gorm.Model

	Name    string `gorm:"unique"`
	Code    string `gorm:"unique"`
	Default bool   `gorm:"default:false"`
}

type Payload struct {
	gorm.Model

	Type      string  `json:"type" gorm:"uniqueIndex:idx_type_pattern"`
	ProjectID uint    `json:"project_id"`
	Project   Project `json:"project"`

	SortOrder int `json:"sort_order"`

	PathPattern string `json:"path_pattern" gorm:"uniqueIndex:idx_type_pattern"`

	Data []byte `json:"data"`
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

		var err error
		db, err = gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
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

	db.Order("sort_order, project, path asc").Find(&payloads)

	return payloads
}
