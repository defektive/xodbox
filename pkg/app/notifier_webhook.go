package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/defektive/xodbox/pkg/app/types"
	"io"
	"net/http"
)

type WebhookNotifier struct {
	name string
	URL  string
}

func NewWebhookNotifier(url string) types.Notifier {
	return &WebhookNotifier{
		name: "WebhookNotifier",
		URL:  url,
	}
}

func (wh *WebhookNotifier) Name() string {
	return wh.name
}

func (wh *WebhookNotifier) Endpoint() string {
	return wh.URL
}

func (wh *WebhookNotifier) Send(event types.InteractionEvent) error {
	jsonBody, err := wh.Payload(event)
	if err != nil {
		lg().Error("error marshaling JSON", "err", err)
		return err
	}

	return WebHookPost(wh.URL, jsonBody)
}

func WebHookPost(url string, payload []byte) error {
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

func (wh *WebhookNotifier) Payload(e types.InteractionEvent) ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%s\n```%s\n```", e.Details(), e.Data()))
}
