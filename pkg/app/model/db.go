package model

import (
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"os"
	"time"
)

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
		db, err = gorm.Open(sqlite.Open("xodbox.db"), &gorm.Config{
			Logger: newLogger,
		})
		if err != nil {
			lg().Error("failed to connect database", "error", err)
			panic(err)
		}

		models := []interface{}{
			&Project{},
			&Payload{},
			&Interaction{},
		}

		err = db.AutoMigrate(models...)
		if err != nil {
			lg().Error("failed to migrate models", "error", err)
		}

		seed(db)
	}
	return db
}

var defaultProject = &Project{
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

//func seed(dbh *gorm.DB) {
//
//	tx := dbh.Model(Project{Default: true}).FirstOrInit(&defaultProject)
//	if tx.Error != nil {
//		lg().Error("failed to seed default project", "error", tx.Error)
//	}
//
//	if defaultProject.ID == 0 {
//		defaultProject.Name = "default"
//		defaultProject.Default = true
//
//		tx = dbh.Save(&defaultProject)
//		if tx.Error != nil {
//			lg().Error("failed to create default project", "error", tx.Error)
//		}
//	}
//}
