package webhook

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defektive/xodbox/pkg/types"
)

// curlEvent is an InteractionEvent that also provides a curl command.
type curlEvent struct {
	*types.BaseEvent
	curl string
}

func (e curlEvent) CurlCommand() string { return e.curl }

func TestChatTextIncludesCurlWhenAvailable(t *testing.T) {
	e := curlEvent{
		BaseEvent: &types.BaseEvent{RawData: []byte("GET /x")},
		curl:      "curl 'http://target/x'",
	}
	txt := ChatText(e)
	if !strings.Contains(txt, "Replay:") || !strings.Contains(txt, "curl 'http://target/x'") {
		t.Errorf("expected replay curl block:\n%s", txt)
	}
}

func TestChatTextOmitsCurlForPlainEvents(t *testing.T) {
	// A bare event is not a CurlProvider — no replay block.
	txt := ChatText(&types.BaseEvent{RawData: []byte("some data")})
	if strings.Contains(txt, "Replay:") {
		t.Errorf("plain event should have no replay block:\n%s", txt)
	}
}

func TestJSONPayloadCurlOmitemptyForPlainEvents(t *testing.T) {
	n := NewNotifier("http://example", "")
	b, err := n.Payload(&types.BaseEvent{RawData: []byte("x")})
	if err != nil {
		t.Fatalf("Payload: %v", err)
	}
	if strings.Contains(string(b), "Curl") {
		t.Errorf("plain event JSON should omit Curl field: %s", b)
	}

	b2, _ := n.Payload(curlEvent{BaseEvent: &types.BaseEvent{}, curl: "curl 'http://t'"})
	var m map[string]any
	if err := json.Unmarshal(b2, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["Curl"] != "curl 'http://t'" {
		t.Errorf("expected Curl field, got %v", m["Curl"])
	}
}
