package httpx

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/defektive/xodbox/pkg/model"
)

func newPayload(data PayloadData) *Payload {
	p := NewHTTPPayload()
	p.Data = data
	return p
}

func TestNewHTTPPayloadType(t *testing.T) {
	p := NewHTTPPayload()
	if p.Type != PayloadName {
		t.Errorf("Type = %q, want %q", p.Type, PayloadName)
	}
}

func TestPayloadTableName(t *testing.T) {
	if got := (&Payload{}).TableName(); got != "payloads" {
		t.Errorf("TableName() = %q, want payloads", got)
	}
}

func TestHasHeaderCaseInsensitive(t *testing.T) {
	p := newPayload(PayloadData{
		Headers: map[string]string{
			"X-Custom-Header": "v",
			"Location":        "/elsewhere",
		},
	})
	if !p.HasHeader("location") {
		t.Error("HasHeader should match Location case-insensitively")
	}
	if !p.HasHeader("X-CUSTOM-HEADER") {
		t.Error("HasHeader should match X-Custom-Header case-insensitively")
	}
	if p.HasHeader("missing") {
		t.Error("HasHeader should be false for absent header")
	}
}

func TestIsRedirect(t *testing.T) {
	yes := newPayload(PayloadData{Headers: map[string]string{"Location": "/x"}})
	no := newPayload(PayloadData{Headers: map[string]string{"X-Other": "y"}})
	if !yes.IsRedirect() {
		t.Error("payload with Location header should be a redirect")
	}
	if no.IsRedirect() {
		t.Error("payload without Location header should not be a redirect")
	}
}

func TestHasStatusCode(t *testing.T) {
	tests := []struct {
		name    string
		payload *Payload
		want    bool
	}{
		{"explicit status", newPayload(PayloadData{StatusCode: "418"}), true},
		{"redirect implies status", newPayload(PayloadData{Headers: map[string]string{"Location": "/x"}}), true},
		{"neither", newPayload(PayloadData{Body: "hello"}), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.payload.HasStatusCode(); got != tc.want {
				t.Errorf("HasStatusCode() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestShouldProcess(t *testing.T) {
	p := newPayload(PayloadData{})
	p.Pattern = `^/api/v[0-9]+/.*$`

	tests := []struct {
		path string
		want bool
	}{
		{"/api/v1/users", true},
		{"/api/v42/things", true},
		{"/api/users", false},
		{"/", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "http://example.com"+tc.path, nil)
			if got := p.ShouldProcess(r); got != tc.want {
				t.Errorf("ShouldProcess(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestHeaderTemplatesParsed(t *testing.T) {
	p := newPayload(PayloadData{
		Headers: map[string]string{
			"X-Static":                   "value",
			"X-{{.NotifyString}}-Header": "static-value",
		},
	})
	templates := p.HeaderTemplates()
	if len(templates) != 2 {
		t.Fatalf("HeaderTemplates len = %d, want 2", len(templates))
	}
	// Second call should be cached (no recompilation).
	if &p.HeaderTemplates()[0] != &templates[0] {
		t.Error("HeaderTemplates should cache the slice across calls")
	}
}

func TestBodyTextTemplateExecutes(t *testing.T) {
	p := newPayload(PayloadData{Body: "hello {{.NotifyString}}"})
	tmpl, err := p.BodyTextTemplate()
	if err != nil {
		t.Fatalf("BodyTextTemplate: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, &TemplateContext{NotifyString: "world"}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if buf.String() != "hello world" {
		t.Errorf("rendered = %q, want %q", buf.String(), "hello world")
	}
}

func TestPayloadTemplatesCannotReadEnv(t *testing.T) {
	t.Setenv("XODBOX_SECRET_TEST", "topsecret")

	// env / expandenv are stripped from the payload FuncMap so an authored
	// payload can never exfiltrate the process environment into a response.
	for _, body := range []string{`{{ env "XODBOX_SECRET_TEST" }}`, `{{ expandenv "$XODBOX_SECRET_TEST" }}`} {
		p := newPayload(PayloadData{Body: body})
		if _, err := p.BodyTextTemplate(); err == nil {
			t.Errorf("payload body %q should fail to parse (env funcs removed), got no error", body)
		}
	}

	if _, ok := payloadFuncMap()["env"]; ok {
		t.Error("payloadFuncMap must not expose env")
	}
	if _, ok := payloadFuncMap()["expandenv"]; ok {
		t.Error("payloadFuncMap must not expose expandenv")
	}
	// A non-env Sprig function should still be available.
	if _, ok := payloadFuncMap()["upper"]; !ok {
		t.Error("payloadFuncMap should still expose ordinary Sprig funcs like upper")
	}
}

func TestBodyHTMLTemplateEscapesContent(t *testing.T) {
	p := newPayload(PayloadData{Body: "<p>{{.NotifyString}}</p>"})
	tmpl, err := p.BodyHTMLTemplate()
	if err != nil {
		t.Fatalf("BodyHTMLTemplate: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, &TemplateContext{NotifyString: "<script>"}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// html/template should escape angle brackets in the substituted value.
	if bytes.Contains(buf.Bytes(), []byte("<script>")) {
		t.Errorf("html/template should have escaped <script>, got %q", buf.String())
	}
}

func TestStatusTemplateExecutes(t *testing.T) {
	p := newPayload(PayloadData{StatusCode: "{{ if .NotifyString }}301{{ else }}200{{ end }}"})

	var buf bytes.Buffer
	if err := p.StatusTemplate().Execute(&buf, &TemplateContext{NotifyString: "x"}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if buf.String() != "301" {
		t.Errorf("status = %q, want 301", buf.String())
	}
}

func TestExecuteBodyTemplateTextAndHTML(t *testing.T) {
	text := newPayload(PayloadData{Body: "raw <hello>"})
	var buf bytes.Buffer
	if err := text.ExecuteBodyTemplate(&buf, nil); err != nil {
		t.Fatalf("text execute: %v", err)
	}
	if buf.String() != "raw <hello>" {
		t.Errorf("text rendered = %q, want %q", buf.String(), "raw <hello>")
	}

	htmlPayload := newPayload(PayloadData{Body: "{{.NotifyString}}"})
	htmlPayload.isHTMLContentType = true
	buf.Reset()
	if err := htmlPayload.ExecuteBodyTemplate(&buf, &TemplateContext{NotifyString: "<b>"}); err != nil {
		t.Fatalf("html execute: %v", err)
	}
	if bytes.Contains(buf.Bytes(), []byte("<b>")) {
		t.Errorf("html template should have escaped output, got %q", buf.String())
	}
}

func TestSortedPayloadsLoadsAndCaches(t *testing.T) {
	// Reset module-level cache so prior tests don't bleed in, and clear
	// the payloads table — other tests (e.g. NewHandler) may have seeded
	// the embedded payloads via Seed(model.DB()).
	payloads = nil
	t.Cleanup(func() { payloads = nil })
	if err := model.DB().Exec("DELETE FROM payloads").Error; err != nil {
		t.Fatalf("clear payloads: %v", err)
	}

	seed := []model.Payload{
		{Name: "p-b", Type: PayloadName, Pattern: "/b", SortOrder: 2},
		{Name: "p-a", Type: PayloadName, Pattern: "/a", SortOrder: 1},
		{Name: "skip-me", Type: "OTHER", Pattern: "/x", SortOrder: 0},
	}
	for i := range seed {
		if err := model.DB().Create(&seed[i]).Error; err != nil {
			t.Fatalf("seed payload: %v", err)
		}
	}

	got := SortedPayloads()
	if len(got) != 2 {
		t.Fatalf("SortedPayloads len = %d, want 2 (OTHER type should be excluded)", len(got))
	}
	if got[0].Name != "p-a" || got[1].Name != "p-b" {
		t.Errorf("order = [%s, %s], want [p-a, p-b]", got[0].Name, got[1].Name)
	}

	// Second call should hit the cache and return the same slice header.
	again := SortedPayloads()
	if len(again) != 2 {
		t.Errorf("cached call len = %d, want 2", len(again))
	}
}
