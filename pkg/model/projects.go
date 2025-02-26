package model

import (
	"gorm.io/gorm"
)

type Project struct {
	gorm.Model

	Name    string `gorm:"unique"`
	Code    string `gorm:"unique"`
	Default bool   `gorm:"default:false"`
}

//var defaultProject *Project

func DefaultProject() *Project {
	return defaultProject
}
