package httpx

import (
	"bytes"
	"fmt"
	"github.com/defektive/xodbox/pkg/model"
	"io"
	"net/http"
	"strconv"
	"strings"
	"text/template"
	"time"
)

const PayloadName = "HTTPX"

// caches payloads so we only load them once
var payloads = []*Payload{}

// Payload is the HTTPX specific payload database model
type Payload struct {
	model.Payload
	Data            PayloadData `json,yaml:"data" gorm:"serializer:json"`
	headerTemplates []*HeaderTemplate
	bodyTemplate    *template.Template
	statusTemplate  *template.Template
}

// PayloadData is used to handle the JSON in the body field of the Payload database model
type PayloadData struct {
	Headers    map[string]string `json,yaml:"headers"`
	Body       string            `json,yaml:"body"`
	StatusCode string            `yaml:"status_code"`
}

// HeaderTemplate is are templates for header keys/values
// this makes it possible to have variables in header keys
//
//	x-{{.GET_headerKey}}: pizza
type HeaderTemplate struct {
	HeaderTemplate *template.Template
	ValueTemplate  *template.Template
}

func NewHTTPPayload() *Payload {
	return &Payload{Payload: model.Payload{Type: PayloadName}}
}

// TableName tells gorm to the payloads table
func (h *Payload) TableName() string {
	return "payloads"
}

// HeaderTemplates initialize and/or return already initialized header templates
func (h *Payload) HeaderTemplates() []*HeaderTemplate {

	if h.headerTemplates == nil {
		var i = 0
		for header, value := range h.Data.Headers {
			t := &HeaderTemplate{
				HeaderTemplate: template.Must(template.New(fmt.Sprintf("HTTP_PAYLOAD_%d_h_header_%d", h.ID, i)).Parse(header)),
				ValueTemplate:  template.Must(template.New(fmt.Sprintf("HTTP_PAYLOAD_%d_h_value_%d", h.ID, i)).Parse(value)),
			}
			h.headerTemplates = append(h.headerTemplates, t)
		}
	}

	return h.headerTemplates
}

// BodyTemplate initialize and/or return already initialized body template
func (h *Payload) BodyTemplate() (*template.Template, error) {
	if h.bodyTemplate == nil {
		tp := template.New(fmt.Sprintf("HTTP_PAYLOAD_%d_body", h.ID))
		return tp.Parse(h.Data.Body)
	}

	return h.bodyTemplate, nil
}

func (h *Payload) ExecuteBodyTemplate(wr io.Writer, data any) error {
	bt, err := h.BodyTemplate()
	if err != nil {
		return err
	}

	return bt.Execute(wr, data)
}

// StatusTemplate initialize and/or return already initialized status template
func (h *Payload) StatusTemplate() *template.Template {
	if h.statusTemplate == nil {
		h.statusTemplate = template.Must(template.New(fmt.Sprintf("%s_status_code", PayloadName)).Parse(h.Data.StatusCode))
	}
	return h.statusTemplate
}

// HasHeader returns true if header exists.
// does not examine headers generated from templates... :(
func (h *Payload) HasHeader(header string) bool {
	for k, _ := range h.Data.Headers {
		if strings.Contains(strings.ToLower(k), strings.ToLower(header)) {
			return true
		}
	}
	return false
}

// HasStatusCode returns true if:
//   - the response template has a status code
//   - or the response is a redirect (HasHeader("location"))
func (h *Payload) HasStatusCode() bool {
	return h.Data.StatusCode != "" || h.IsRedirect()
}

// IsRedirect is a shortcut for HasHeader("location")... wow I am lazy
func (h *Payload) IsRedirect() bool {
	return h.HasHeader("Location")
}

// ShouldProcess is used to determine if a http.Request should be handled by this Payload
func (h *Payload) ShouldProcess(r *http.Request) bool {
	return h.PatternRegexp().MatchString(r.URL.Path)
}

// Process this is where the magic happens.
func (h *Payload) Process(w http.ResponseWriter, e *Event, templateData map[string]string) {

	tc := e.TemplateContext(templateData)

	for _, headTemplates := range h.HeaderTemplates() {
		var hdrBytes bytes.Buffer
		var valBytes bytes.Buffer
		err := headTemplates.HeaderTemplate.Execute(&hdrBytes, tc)
		if err != nil {
			lg().Error("Error executing header template", "err", err)
		}
		err = headTemplates.ValueTemplate.Execute(&valBytes, tc)
		if err != nil {
			lg().Error("Error executing header value template", "err", err)
		}

		w.Header().Set(hdrBytes.String(), valBytes.String())
	}

	if h.HasStatusCode() {
		var statusBytes bytes.Buffer
		err := h.StatusTemplate().Execute(&statusBytes, tc)
		if err != nil {
			lg().Error("Error executing body template", "err", err)
		}

		responseStatus, err := strconv.Atoi(statusBytes.String())
		if err != nil {
			lg().Error("Error converting response status to int", "err", err)
			responseStatus = 500
		}

		w.WriteHeader(responseStatus)
	}

	if h.InternalFunction == InternalFnInspect {
		// ghetto hack cause I am lazy
		err := Inspect(w, e)
		if err != nil {
			lg().Error("Error executing inspect template", "err", err)
		}
		return
	}

	err := h.ExecuteBodyTemplate(w, tc)
	if err != nil {
		lg().Error("Error executing body template", "err", err)
		fmt.Fprint(w, "that was unexpected")

	}
}

func SortedPayloads() []*Payload {

	if len(payloads) == 0 {
		loadStart := time.Now()
		lg().Warn("Loading payloads")
		model.DB().Where("type = ?", PayloadName).Order("sort_order, project_id, pattern asc").Find(&payloads)
		timeTaken := time.Now().Sub(loadStart)
		lg().Debug("Loading payloads", "timeTaken", timeTaken)
	}

	return payloads
}
