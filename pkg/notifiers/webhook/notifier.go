package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/defektive/xodbox/pkg/types"
)

type Notifier struct {
	name   string
	URL    string
	filter *regexp.Regexp
}

// NewNotifierFromConfig creates a standalone webhook notifier from a YAML
// config map. Recognized keys: "url" (required), "filter" (optional,
// defaults to ".*").
func NewNotifierFromConfig(cfg map[string]string) types.Notifier {
	return NewNotifier(cfg["url"], cfg["filter"])
}

func NewNotifier(url string, filter string) *Notifier {

	if filter == "" {
		filter = ".*"
	}

	return &Notifier{
		name:   "WebhookNotifier",
		URL:    url,
		filter: regexp.MustCompile(filter),
	}
}

func (wh *Notifier) Name() string {
	return wh.name
}

func (wh *Notifier) Filter() *regexp.Regexp {
	return wh.filter
}

func (wh *Notifier) Send(event types.InteractionEvent) error {
	if !ShouldSend(wh.filter, event) {
		return nil
	}
	jsonBody, err := wh.Payload(event)
	if err != nil {
		lg().Error("error marshaling JSON", "err", err)
		return err
	}

	return SendPost(wh.URL, jsonBody)
}

func SendPost(url string, payload []byte) error {
	// #nosec G107 -- the webhook URL is operator config; sending to it
	// is the point of the notifier.
	res, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		lg().Error("Webhook notification error", "err", err)
		return err
	}
	defer res.Body.Close()

	if res.StatusCode > 399 {
		b, _ := io.ReadAll(res.Body)
		lg().Error("Webhook notification error", "StatusCode", res.StatusCode, "body", string(b))
		return err
	}

	lg().Info("Webhook notification sent", "status", res.StatusCode)
	return nil
}

// webhookMaxField caps individual string fields in the JSON webhook payload.
// Most generic webhook receivers impose some body-size limit; 32 KB per field
// keeps total payload well under common ceilings while preserving enough
// context to be useful.
const webhookMaxField = 32 * 1024

type jsonEvent struct {
	RemoteAddr string      `json:"RemoteAddr"`
	RemotePort int         `json:"RemotePort"`
	UserAgent  string      `json:"UserAgent"`
	Data       interface{} `json:"Data"`
	Details    string      `json:"Details"`
	Curl       string      `json:"Curl,omitempty"`
	Sink       *jsonSink   `json:"Sink,omitempty"`
	Truncated  bool        `json:"Truncated,omitempty"`
}

type jsonSink struct {
	Slug        string `json:"Slug"`
	Description string `json:"Description,omitempty"`
	Link        string `json:"Link,omitempty"`
}

func (wh *Notifier) Payload(e types.InteractionEvent) ([]byte, error) {
	data := e.Data()
	curl := CurlCommand(e)
	truncated := false
	if len(data) > webhookMaxField {
		data = data[:webhookMaxField] + "…"
		truncated = true
	}
	if len(curl) > webhookMaxField {
		curl = curl[:webhookMaxField] + "…"
		truncated = true
	}

	res := jsonEvent{
		RemoteAddr: e.RemoteIP(),
		RemotePort: e.RemotePort(),
		UserAgent:  e.UserAgent(),
		Data:       data,
		Details:    e.Details(),
		Curl:       curl,
		Sink:       sinkInfo(e),
		Truncated:  truncated,
	}

	return json.Marshal(res)
}

// ShouldSend reports whether a notifier should deliver the event. It returns
// true when the event bypasses filters (e.g. sink-hit events) or when the
// filter regex matches the event's FilterString.
func ShouldSend(filter *regexp.Regexp, e types.InteractionEvent) bool {
	if fb, ok := e.(types.FilterBypasser); ok && fb.BypassFilter() {
		return true
	}
	return filter.MatchString(e.FilterString())
}

func FilterMatches(filter *regexp.Regexp, data string) bool {
	return filter.MatchString(data)
}

// CurlCommand returns a replay curl command for events that can produce one
// (HTTP), or "" otherwise.
func CurlCommand(e types.InteractionEvent) string {
	if cp, ok := e.(types.CurlProvider); ok {
		return cp.CurlCommand()
	}
	return ""
}

// TruncateChat truncates a chat message to max characters, closing any open
// markdown code block so the rendering isn't broken.
func TruncateChat(s string, max int) string {
	if len(s) <= max {
		return s
	}
	const suffix = "\n…\n```"
	cut := s[:max-len(suffix)]
	if strings.Count(cut, "```")%2 == 1 {
		return cut + suffix
	}
	return cut + "\n…"
}

// isBinary reports whether data looks like binary content (contains null
// bytes or a high ratio of non-printable characters). Binary data renders
// as garbage in chat code blocks, so callers replace it with a placeholder.
func isBinary(s string) bool {
	if strings.ContainsRune(s, '\x00') {
		return true
	}
	if len(s) == 0 {
		return false
	}
	nonPrint := 0
	check := s
	if len(check) > 512 {
		check = check[:512]
	}
	for _, b := range []byte(check) {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			nonPrint++
		}
	}
	return nonPrint*4 > len(check)
}

// ChatText renders the standard chat-notifier body: the event details, its
// raw data in a code block, and — when available — a curl command to replay
// the request in a second code block. Sink-hit events get an enriched header.
// Binary data is replaced with a placeholder to avoid garbled chat messages.
func ChatText(e types.InteractionEvent) string {
	var sb strings.Builder
	if sh, ok := e.(types.SinkHitProvider); ok {
		sb.WriteString(fmt.Sprintf("*Sink hit: %s*", sh.SinkSlug()))
		if desc := sh.SinkDescription(); desc != "" {
			sb.WriteString(fmt.Sprintf("\n> %s", desc))
		}
		if link := sh.SinkLink(); link != "" {
			sb.WriteString(fmt.Sprintf("\nLink: %s", link))
		}
		sb.WriteString("\n\n")
	}
	data := e.Data()
	if isBinary(data) {
		data = fmt.Sprintf("(%d bytes of binary data)", len(data))
	}
	sb.WriteString(fmt.Sprintf("%s\n```%s\n```", e.Details(), data))
	if curl := CurlCommand(e); curl != "" {
		sb.WriteString(fmt.Sprintf("\nReplay:\n```%s\n```", curl))
	}
	return sb.String()
}

// sinkInfo extracts sink metadata from a SinkHitProvider event, or nil.
func sinkInfo(e types.InteractionEvent) *jsonSink {
	sh, ok := e.(types.SinkHitProvider)
	if !ok {
		return nil
	}
	return &jsonSink{
		Slug:        sh.SinkSlug(),
		Description: sh.SinkDescription(),
		Link:        sh.SinkLink(),
	}
}
