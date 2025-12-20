package model

import "gorm.io/gorm"

type Interaction struct {
	gorm.Model

	PayloadID uint    `json:"payload_id"`
	Payload   Payload `json:"-"`

	ProjectID uint    `json:"project_id"`
	Project   Project `json:"-"`

	RemoteAddr    string `json:"remote_addr" gorm:"index:idx_remote_client"`
	RemotePort    string `json:"remote_port"`
	Handler       string `json:"handler"`
	RequestType   string `json:"request_type"`
	RequestTarget string `json:"request_target"`
	Protocol      string `json:"protocol"`
	UserAgent     string `json:"user_agent" gorm:"index:idx_remote_client"`
	Headers       string `json:"headers"`

	Data []byte `json:"data"`
}

func SortedInteractions(limit int) []Interaction {
	var interactions = []Interaction{}
	DB().Order("created_at desc").Limit(limit).Find(&interactions)
	return interactions
}

type Result struct {
	RemoteAddr  string `json:"remote_addr"`
	Total       int64  `json:"total"`
	MinuteGroup int64  `json:"minute_group"`
}

func getBotQuery() *gorm.DB {
	return db.Model(&Interaction{}).
		Select("remote_addr, count(*) total, strftime('%Y-%m-%d %H:%M', created_at) AS minute_group").
		Group("minute_group").
		Having("count(*) > 30")
}

func Bots() []Result {

	var results []Result
	getBotQuery().
		Find(&results)

	return results
}

func IsBot(remoteAddr string) bool {

	var results []Result
	getBotQuery().
		Where("remote_addr = ?", remoteAddr).
		Find(&results)

	return len(results) > 0
}
