package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/defektive/xodbox/pkg/app/types"
	"io"
	"log"
	"net/http"
	"regexp"
)

type Notifier struct {
	name   string
	URL    string
	filter *regexp.Regexp
}

func NewWebhookNotifier(url string, filter string) types.Notifier {

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

func (wh *Notifier) Endpoint() string {
	return wh.URL
}

func (wh *Notifier) Send(event types.InteractionEvent) error {

	log.Println("here")

	jsonBody, err := wh.Payload(event)
	if err != nil {
		lg().Error("error marshaling JSON", "err", err)
		return err
	}

	return SendPost(wh.URL, jsonBody)
}

func SendPost(url string, payload []byte) error {
	res, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		lg().Error("Slack notification error", "err", err)
		return err
	}

	if res.StatusCode > 399 {
		b, _ := io.ReadAll(res.Body)
		lg().Error("Slack notification error", "StatusCode", res.StatusCode, "body", string(b))
		return err
	}

	lg().Info("Slack notification sent", "status", res.StatusCode)
	return nil
}

func (wh *Notifier) Payload(e types.InteractionEvent) ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%s\n```%s\n```", e.Details(), e.Data()))
}

func FilterMatches(filter *regexp.Regexp, data string) bool {
	return filter.MatchString(data)
}
