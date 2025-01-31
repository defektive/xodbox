package httpx

import (
	"bytes"
	"fmt"
	"github.com/defektive/xodbox/pkg/app/model"
	"gorm.io/gorm"
	"net/http"
	"strings"
	"text/template"
	"time"
)

type HTTPPayload struct {
	model.Payload
	Data PayloadData `gorm:"serializer:json"`
}

const PayloadName = "HTTPX"

type HeaderTemplate struct {
	HeaderTemplate *template.Template
	ValueTemplate  *template.Template
}

type PayloadData struct {
	Headers         map[string]string `json:"headers"`
	Body            []byte            `json:"body"`
	headerTemplates []*HeaderTemplate
	bodyTemplate    *template.Template
}

func CreateTemplate(name, t string) *template.Template {
	return template.Must(template.New(name).Parse(t))
}

func (p *PayloadData) HeaderTemplates(tplName string) []*HeaderTemplate {

	if p.headerTemplates == nil {
		var i = 0
		for header, value := range p.Headers {
			t := &HeaderTemplate{
				HeaderTemplate: CreateTemplate(fmt.Sprintf("%s_h_header_%d", tplName, i), header),
				ValueTemplate:  CreateTemplate(fmt.Sprintf("%s_h_value_%d", tplName, i), value),
			}
			p.headerTemplates = append(p.headerTemplates, t)
		}
	}

	return p.headerTemplates

}

func (p *PayloadData) BodyTemplate(tplName string) *template.Template {
	if p.bodyTemplate == nil {
		p.bodyTemplate = CreateTemplate(fmt.Sprintf("%s_body", tplName), string(p.Body))
	}

	return p.bodyTemplate
}

func NewHTTPPayload() *HTTPPayload {
	return &HTTPPayload{Payload: model.Payload{Type: PayloadName}}
}

func (payload *HTTPPayload) TableName() string {
	return "payloads"
}

func (h *HTTPPayload) ShouldHandle(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, h.PathPattern)
}

func (h *HTTPPayload) Process(w http.ResponseWriter, r *http.Request) {

	key := fmt.Sprintf("http_payload_%d", h.ID)
	headers := h.Data.HeaderTemplates(key)
	body := h.Data.BodyTemplate(key)

	for _, hdrTpls := range headers {
		var hdrBytes bytes.Buffer
		var valBytes bytes.Buffer
		err := hdrTpls.HeaderTemplate.Execute(&hdrBytes, hdrTpls.HeaderTemplate)
		if err != nil {
			lg().Error("Error executing header template: ", "err", err)
		}
		err = hdrTpls.ValueTemplate.Execute(&valBytes, hdrTpls.HeaderTemplate)
		if err != nil {
			lg().Error("Error executing header value template: ", "err", err)
		}

		w.Header().Set(hdrBytes.String(), valBytes.String())
	}

	err := body.Execute(w, map[string]string{
		"ProxySrvRegex": "127\\.0\\.0\\.1",
		"ProxySrv":      "127.0.0.1",
		"Host":          r.URL.Host,
		"AlertPattern":  "l",
	})

	if err != nil {
		lg().Error("Error executing body template: ", "err", err)
	}
}

func init() {
	//payloads = append(payloads, &BreakfastBot{})
	//payloads = append(payloads, &RequestReflectionPayload{})

	initSimplePayloads()

	Seed(model.DB())
}

func Seed(dbh *gorm.DB) {

	h := NewHTTPPayload()

	h.PathPattern = "/"
	h.SortOrder = -1000
	h.Data = PayloadData{
		Headers: map[string]string{
			"Server": "BreakfastBot/1.0.0",
		},
	}
	h.Project = model.DefaultProject()

	tx := dbh.Create(h)

	h = NewHTTPPayload()

	h.PathPattern = "/fast"
	h.Data = PayloadData{
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: []byte(`{"data":"hello world"}`),
	}
	h.Project = model.DefaultProject()

	tx = dbh.Create(h)
	if tx.Error != nil {
		lg().Error("Error seeding database payload", "err", tx.Error)
	}

}

var payloads = []*HTTPPayload{}

func SortedPayloads() []*HTTPPayload {

	if len(payloads) == 0 {
		loadStart := time.Now()
		lg().Warn("Loading payloads")
		model.DB().Where("type = ?", PayloadName).Order("sort_order, project_id, path_pattern asc").Find(&payloads)
		timeTaken := time.Now().Sub(loadStart)
		lg().Debug("Loading payloads", "timeTaken", timeTaken)
	}

	return payloads
}
