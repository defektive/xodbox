package models

import (
	"gorm.io/gorm"
)

type Project struct {
	gorm.Model

	Name string `gorm:"unique"`
}

type Payload struct {
	gorm.Model

	HandlerName string  `json:"handler_name"`
	ProjectID   uint    `json:"project_id"`
	Project     Project `json:"project"`

	Filter string `json:"filter"`
	Data   []byte `json:"data"`
}

type Interaction struct {
	gorm.Model

	PayloadID  uint    `json:"payload_id"`
	Payload    Payload `json:"payload"`
	ProjectID  uint    `json:"project_id"`
	Project    Project `json:"project"`
	RemoteAddr string  `json:"remote_addr"`
	RemotePort string  `json:"remote_port"`
	Data       []byte  `json:"data"`
}
