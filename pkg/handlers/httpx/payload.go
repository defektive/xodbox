package httpx

import (
	"bytes"
	"fmt"
	htmlTemplate "html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	textTemplate "text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/defektive/xodbox/pkg/model"
)

const PayloadName = "HTTPX"

// caches payloads so we only load them once
var payloads = []*Payload{}

// Payload is the HTTPX specific payload database model
type Payload struct {
	model.Payload
	Data            PayloadData `json,yaml:"data" gorm:"serializer:json"`
	headerTemplates []*HeaderTemplate

	isHTMLContentType bool

	bodyTextTemplate *textTemplate.Template
	bodyHTMLTemplate *htmlTemplate.Template
	statusTemplate   *textTemplate.Template
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
	HeaderTemplate *textTemplate.Template
	ValueTemplate  *textTemplate.Template
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
				HeaderTemplate: textTemplate.Must(textTemplate.New(fmt.Sprintf("HTTP_PAYLOAD_%d_h_header_%d", h.ID, i)).Funcs(sprig.FuncMap()).Parse(header)),
				ValueTemplate:  textTemplate.Must(textTemplate.New(fmt.Sprintf("HTTP_PAYLOAD_%d_h_value_%d", h.ID, i)).Funcs(sprig.FuncMap()).Parse(value)),
			}
			h.headerTemplates = append(h.headerTemplates, t)
		}
	}

	return h.headerTemplates
}

// BodyTextTemplate initialize and/or return already initialized body textTemplate
func (h *Payload) BodyTextTemplate() (*textTemplate.Template, error) {
	if h.bodyTextTemplate == nil {
		tp := textTemplate.New(fmt.Sprintf("HTTP_PAYLOAD_%d_body", h.ID)).Funcs(sprig.FuncMap())
		return tp.Parse(h.Data.Body)
	}

	return h.bodyTextTemplate, nil
}

// BodyHTMLTemplate initialize and/or return already initialized body textTemplate
func (h *Payload) BodyHTMLTemplate() (*htmlTemplate.Template, error) {
	if h.bodyHTMLTemplate == nil {
		tp := htmlTemplate.New(fmt.Sprintf("HTTP_PAYLOAD_%d_body", h.ID)).Funcs(sprig.FuncMap())
		return tp.Parse(h.Data.Body)
	}

	return h.bodyHTMLTemplate, nil
}

func (h *Payload) ExecuteBodyTemplate(wr io.Writer, data any) error {
	if h.isHTMLContentType {
		// lolz... not sure why I am protecting against XSS... this while project is about reflecting data
		bt, err := h.BodyHTMLTemplate()
		if err != nil {
			return err
		}

		return bt.Execute(wr, data)
	} else {
		bt, err := h.BodyTextTemplate()
		if err != nil {
			return err
		}

		return bt.Execute(wr, data)
	}
}

// StatusTemplate initialize and/or return already initialized status textTemplate
func (h *Payload) StatusTemplate() *textTemplate.Template {
	if h.statusTemplate == nil {
		h.statusTemplate = textTemplate.Must(textTemplate.New(fmt.Sprintf("%s_status_code", PayloadName)).Funcs(sprig.FuncMap()).Parse(h.Data.StatusCode))
	}
	return h.statusTemplate
}

// HasHeader returns true if header exists.
// does not examine headers generated from templates... :(
func (h *Payload) HasHeader(header string) bool {
	for k := range h.Data.Headers {
		if strings.Contains(strings.ToLower(k), strings.ToLower(header)) {
			return true
		}
	}
	return false
}

// HasStatusCode returns true if:
//   - the response textTemplate has a status code
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
func (h *Payload) Process(w http.ResponseWriter, e *Event, handler *Handler) {

	tc := e.TemplateContext(handler.app.GetTemplateData())

	for _, headTemplates := range h.HeaderTemplates() {
		var hdrBytes bytes.Buffer
		var valBytes bytes.Buffer
		err := headTemplates.HeaderTemplate.Execute(&hdrBytes, tc)
		if err != nil {
			lg().Error("Error executing header textTemplate", "payload", h.Name, "err", err)
		}
		err = headTemplates.ValueTemplate.Execute(&valBytes, tc)
		if err != nil {
			lg().Error("Error executing header value textTemplate", "payload", h.Name, "err", err)
		}

		headerKey := hdrBytes.String()
		headerVal := valBytes.String()
		if strings.ToLower(headerKey) == "content-type" && strings.ToLower(headerVal) == "text/html" {
			h.isHTMLContentType = true
		}

		w.Header().Set(headerKey, valBytes.String())
	}

	if h.HasStatusCode() {
		var statusBytes bytes.Buffer
		err := h.StatusTemplate().Execute(&statusBytes, tc)
		if err != nil {
			lg().Error("Error executing body textTemplate", "payload", h.Name, "err", err)
		}

		responseStatus, err := strconv.Atoi(statusBytes.String())
		if err != nil {
			lg().Error("Error converting response status to int", "payload", h.Name, "err", err)
			responseStatus = 500
		}

		w.WriteHeader(responseStatus)
	}

	// TODO: If this is still a ghetto if statement.... we should make it more elegant if there are more than 3 blocks
	if h.InternalFunction == InternalFnInspect {
		// ghetto hack cause I am lazy
		if err := Inspect(w, e); err != nil {
			lg().Error("Error executing build textTemplate", "payload", h.Name, "err", err)
		}
		return
	} else if h.InternalFunction == InternalFnBuild {
		lg().Debug("building payload", "payload", h.Name, "payload", h)
		if err := Build(w, e, handler); err != nil {
			lg().Error("Error executing build textTemplate", "payload", h.Name, "err", err)
		}
		return
	}

	err := h.ExecuteBodyTemplate(w, tc)
	if err != nil {
		lg().Error("Error executing body textTemplate", "payload", h.Name, "err", err)
		fmt.Fprint(w, "that was unexpected")
	}
}

func SortedPayloads() []*Payload {

	if len(payloads) == 0 {
		loadStart := time.Now()
		lg().Warn("Loading payloads")
		model.DB().Where("type = ?", PayloadName).Order("sort_order, project_id, pattern asc").Find(&payloads)
		timeTaken := time.Since(loadStart)
		lg().Debug("Loading payloads", "timeTaken", timeTaken)
	}

	return payloads
}
