package httpx

import (
	"bytes"
	"fmt"
	"github.com/defektive/xodbox/pkg/app/model"
	"net/http"
	"net/http/httputil"
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
	Body            string            `json:"body"`
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

func (h *HTTPPayload) TableName() string {
	return "payloads"
}

func (h *HTTPPayload) ShouldHandle(r *http.Request) bool {
	return h.PatternRegexp().MatchString(r.URL.Path)
}

func (h *HTTPPayload) Process(w http.ResponseWriter, r *http.Request, templateData map[string]string) {

	key := fmt.Sprintf("http_payload_%d", h.ID)
	headers := h.Data.HeaderTemplates(key)
	body := h.Data.BodyTemplate(key)

	fullRequestBytes, _ := httputil.DumpRequest(r, true)
	requestStr := string(fullRequestBytes)

	templateData["Host"] = r.Host
	templateData["Host"] = requestStr

	for _, headTemplates := range headers {
		var hdrBytes bytes.Buffer
		var valBytes bytes.Buffer
		err := headTemplates.HeaderTemplate.Execute(&hdrBytes, templateData)
		if err != nil {
			lg().Error("Error executing header template: ", "err", err)
		}
		err = headTemplates.ValueTemplate.Execute(&valBytes, templateData)
		if err != nil {
			lg().Error("Error executing header value template: ", "err", err)
		}

		w.Header().Set(hdrBytes.String(), valBytes.String())
	}

	if h.Pattern == InspectPattern {
		// ghetto hack cause I am lazy
		Inspect(w, r, requestStr)
		return
	}

	err := body.Execute(w, templateData)
	if err != nil {
		lg().Error("Error executing body template: ", "err", err)
	}
}

func init() {
	Seed(model.DB())
}

var payloads = []*HTTPPayload{}

func SortedPayloads() []*HTTPPayload {

	if len(payloads) == 0 {
		loadStart := time.Now()
		lg().Warn("Loading payloads")
		model.DB().Where("type = ?", PayloadName).Order("sort_order, project_id, pattern asc").Find(&payloads)
		timeTaken := time.Now().Sub(loadStart)
		lg().Debug("Loading payloads", "timeTaken", timeTaken)
	}

	return payloads
}
