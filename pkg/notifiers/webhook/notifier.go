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
	if !FilterMatches(wh.filter, event.FilterString()) {
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

type jsonEvent struct {
	RemoteAddr string      `json:"RemoteAddr"`
	RemotePort int         `json:"RemotePort"`
	UserAgent  string      `json:"UserAgent"`
	Data       interface{} `json:"Data"`
	Details    string      `json:"Details"`
	Curl       string      `json:"Curl,omitempty"`
	Sink       *jsonSink   `json:"Sink,omitempty"`
}

type jsonSink struct {
	Slug        string `json:"Slug"`
	Description string `json:"Description,omitempty"`
	Link        string `json:"Link,omitempty"`
}

func (wh *Notifier) Payload(e types.InteractionEvent) ([]byte, error) {

	res := jsonEvent{
		RemoteAddr: e.RemoteIP(),
		RemotePort: e.RemotePort(),
		UserAgent:  e.UserAgent(),
		Data:       e.Data(),
		Details:    e.Details(),
		Curl:       CurlCommand(e),
		Sink:       sinkInfo(e),
	}

	return json.Marshal(res)
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

// ChatText renders the standard chat-notifier body: the event details, its
// raw data in a code block, and — when available — a curl command to replay
// the request in a second code block. Sink-hit events get an enriched header.
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
	sb.WriteString(fmt.Sprintf("%s\n```%s\n```", e.Details(), e.Data()))
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
