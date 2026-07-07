package httpx

import (
	"bytes"
	"testing"
)

// A malformed text body template should surface a parse error rather than
// panicking — BodyTextTemplate uses Parse (not Must) so the error is returned.
func TestBodyTextTemplateParseError(t *testing.T) {
	p := newPayload(PayloadData{Body: "{{ .Broken "})
	if _, err := p.BodyTextTemplate(); err == nil {
		t.Error("BodyTextTemplate should return error on malformed template")
	}
}

func TestBodyHTMLTemplateParseError(t *testing.T) {
	p := newPayload(PayloadData{Body: "{{ .Broken "})
	if _, err := p.BodyHTMLTemplate(); err == nil {
		t.Error("BodyHTMLTemplate should return error on malformed template")
	}
}

// ExecuteBodyTemplate must propagate the parse error from the underlying
// template builder for both the text and HTML branches.
func TestExecuteBodyTemplateTextParseError(t *testing.T) {
	p := newPayload(PayloadData{Body: "{{ .Broken "})
	var buf bytes.Buffer
	if err := p.ExecuteBodyTemplate(&buf, nil); err == nil {
		t.Error("ExecuteBodyTemplate (text) should return parse error")
	}
}

func TestExecuteBodyTemplateHTMLParseError(t *testing.T) {
	p := newPayload(PayloadData{Body: "{{ .Broken "})
	p.isHTMLContentType = true
	var buf bytes.Buffer
	if err := p.ExecuteBodyTemplate(&buf, nil); err == nil {
		t.Error("ExecuteBodyTemplate (html) should return parse error")
	}
}
