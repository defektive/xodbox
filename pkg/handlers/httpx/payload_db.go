package httpx

import (
	"bytes"
	"fmt"
	"github.com/analog-substance/util/cli/build_info"
	"github.com/defektive/xodbox/pkg/app/model"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"text/template"
	"time"
)

type HTTPPayload struct {
	model.Payload
	Data PayloadData `json,yaml:"data" gorm:"serializer:json"`

	headerTemplates []*HeaderTemplate
	bodyTemplate    *template.Template
	statusTemplate  *template.Template
}

const PayloadName = "HTTPX"

type HeaderTemplate struct {
	HeaderTemplate *template.Template
	ValueTemplate  *template.Template
}

type PayloadData struct {
	StatusCode string            `json,yaml:"status_code"`
	Headers    map[string]string `json,yaml:"headers"`
	Body       string            `json,yaml:"body"`
}

func CreateTemplate(name, t string) *template.Template {
	return template.Must(template.New(name).Parse(t))
}

func (h *HTTPPayload) HeaderTemplates() []*HeaderTemplate {

	if h.headerTemplates == nil {
		var i = 0
		for header, value := range h.Data.Headers {
			t := &HeaderTemplate{
				HeaderTemplate: CreateTemplate(fmt.Sprintf("HTTP_PAYLOAD_%d_h_header_%d", h.ID, i), header),
				ValueTemplate:  CreateTemplate(fmt.Sprintf("HTTP_PAYLOAD_%d_h_value_%d", h.ID, i), value),
			}
			h.headerTemplates = append(h.headerTemplates, t)
		}
	}

	return h.headerTemplates
}

func (h *HTTPPayload) BodyTemplate() *template.Template {
	if h.bodyTemplate == nil {
		h.bodyTemplate = CreateTemplate(fmt.Sprintf("HTTP_PAYLOAD_%d_body", h.ID), h.Data.Body)
	}

	return h.bodyTemplate
}

func (h *HTTPPayload) StatusTemplate() *template.Template {
	if h.statusTemplate == nil {
		h.statusTemplate = CreateTemplate(fmt.Sprintf("%s_status_code", PayloadName), h.Data.StatusCode)
	}
	return h.statusTemplate
}

func (h *HTTPPayload) HasHeader(header string) bool {
	for k, _ := range h.Data.Headers {
		if strings.Contains(strings.ToLower(k), strings.ToLower(header)) {
			return true
		}
	}
	return false
}

func (h *HTTPPayload) HasStatusCode() bool {
	return h.Data.StatusCode != "" || h.IsRedirect()
}

func (h *HTTPPayload) IsRedirect() bool {
	return h.HasHeader("Location")
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

func (h *HTTPPayload) Process(w http.ResponseWriter, r *http.Request, body []byte, templateData map[string]string) {

	fullRequestBytes, _ := httputil.DumpRequest(r, true)
	requestStr := string(fullRequestBytes)

	templateData["Version"] = build_info.GetLoadedVersion().Version
	templateData["Host"] = r.Host
	templateData["Path"] = r.URL.Path
	templateData["Body"] = requestStr

	if h.HasStatusCode() {
		var statusBytes bytes.Buffer
		err := h.StatusTemplate().Execute(&statusBytes, templateData)
		if err != nil {
			lg().Error("Error executing body template: ", "err", err)
		}

		responseStatus, err := strconv.Atoi(statusBytes.String())
		if err != nil {
			lg().Error("Error converting response status to int: ", "err", err)
			responseStatus = 500
		}

		w.WriteHeader(responseStatus)
	}

	for param, vals := range r.URL.Query() {
		if len(vals) > 1 {
			for idx, val := range vals {
				templateData[fmt.Sprintf("GET_%s_%d", param, idx)] = val
			}
		} else if len(vals) == 1 {
			templateData[fmt.Sprintf("GET_%s", param)] = vals[0]
		}
	}

	for _, headTemplates := range h.HeaderTemplates() {
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

	if h.InternalFunction == InternalFnInspect {
		// ghetto hack cause I am lazy
		err := Inspect(w, r, body, requestStr)
		if err != nil {
			lg().Error("Error executing inspect template: ", "err", err)
		}
		return
	}

	err := h.BodyTemplate().Execute(w, templateData)
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
