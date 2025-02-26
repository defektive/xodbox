package model

import (
	"gorm.io/gorm"
	"regexp"
)

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

	Type      string   `json,yaml:"type"`
	ProjectID uint     `json,yaml:"project_id"`
	Project   *Project `yaml:"-" yaml:"-"`

	SortOrder int `yaml:"sort_order"`

	Pattern          string `json,yaml:"pattern"`
	InternalFunction string `json,yaml:"internal_function"`
	IsFinal          bool   `json,yaml:"is_final"`

	Data string `json,yaml:"data"`

	patternRegexp *regexp.Regexp
}

func (p *Payload) PatternRegexp() *regexp.Regexp {
	if p.patternRegexp == nil {
		p.patternRegexp = regexp.MustCompile(p.Pattern)
	}

	return p.patternRegexp
}

func SortedPayloads() []Payload {

	var payloads = []Payload{}

	db.Order("sort_order, project_id, pattern asc").Find(&payloads)

	return payloads
}
