package model

import "gorm.io/gorm"

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
