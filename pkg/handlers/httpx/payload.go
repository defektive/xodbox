package httpx

import (
	"bytes"
	"fmt"
	"github.com/analog-substance/util/cli/build_info"
	"github.com/defektive/xodbox/pkg/app/model"
	"github.com/defektive/xodbox/pkg/app/util"
	"net/http"
	"net/http/httputil"
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
	Data PayloadData `json,yaml:"data" gorm:"serializer:json"`

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
				HeaderTemplate: util.CreateTemplate(fmt.Sprintf("HTTP_PAYLOAD_%d_h_header_%d", h.ID, i), header),
				ValueTemplate:  util.CreateTemplate(fmt.Sprintf("HTTP_PAYLOAD_%d_h_value_%d", h.ID, i), value),
			}
			h.headerTemplates = append(h.headerTemplates, t)
		}
	}

	return h.headerTemplates
}

// BodyTemplate initialize and/or return already initialized body template
func (h *Payload) BodyTemplate() *template.Template {
	if h.bodyTemplate == nil {
		h.bodyTemplate = util.CreateTemplate(fmt.Sprintf("HTTP_PAYLOAD_%d_body", h.ID), h.Data.Body)
	}

	return h.bodyTemplate
}

// StatusTemplate initialize and/or return already initialized status template
func (h *Payload) StatusTemplate() *template.Template {
	if h.statusTemplate == nil {
		h.statusTemplate = util.CreateTemplate(fmt.Sprintf("%s_status_code", PayloadName), h.Data.StatusCode)
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
func (h *Payload) Process(w http.ResponseWriter, r *http.Request, body []byte, templateData map[string]string) {

	fullRequestBytes, _ := httputil.DumpRequest(r, true)
	requestStr := string(fullRequestBytes)

	remoteAddrs := []string{r.RemoteAddr}
	headerIP := r.Header.Get("X-Forwarded-For")
	if headerIP != "" {
		remoteAddrs = append(remoteAddrs, headerIP)
	}
	headerIP = r.Header.Get("X-Real-IP")
	if headerIP != "" {
		remoteAddrs = append(remoteAddrs, headerIP)
	}

	templateData["Version"] = build_info.GetLoadedVersion().Version
	templateData["RemoteAddr"] = strings.Join(remoteAddrs, ", ")
	templateData["UserAgent"] = r.UserAgent()

	templateData["UserAgent"] = r.RemoteAddr

	templateData["Host"] = r.Host
	templateData["Path"] = r.URL.Path
	templateData["Body"] = requestStr

	templateData["CallBackImageURL"] = fmt.Sprintf("http://%s%s?&xdbxImage", r.Host, r.RequestURI)
	templateData["CallBackURL"] = fmt.Sprintf("http://%s%s?&xdbx", r.Host, r.RequestURI)

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
