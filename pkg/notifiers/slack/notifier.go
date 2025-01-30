package slack

import (
	"encoding/json"
	"fmt"
	"github.com/defektive/xodbox/pkg/app/types"
	"github.com/defektive/xodbox/pkg/notifiers/webhook"
)

type SlackWebhookPost struct {
	Channel   string `json:"channel"`
	Username  string `json:"username"`
	IconEmoji string `json:"icon_emoji"`
	Text      string `json:"text"`
}

type SlackWebhookNotifier struct {
	types.Notifier
	Channel string
	User    string
	Icon    string
}

func NewSlackWebhookNotifier(url, channel, user, icon string) types.Notifier {
	return &SlackWebhookNotifier{
		Notifier: webhook.NewWebhookNotifier(url),
		Channel:  channel,
		User:     user,
		Icon:     icon,
	}
}

func (wh *SlackWebhookNotifier) Payload(e types.InteractionEvent) ([]byte, error) {
	postBody := SlackWebhookPost{
		Channel:   wh.Channel,
		Username:  wh.User,
		IconEmoji: wh.Icon,
		Text:      fmt.Sprintf("%s\n```%s\n```", e.Details(), e.Data()),
	}

	return json.Marshal(postBody)
}

func (wh *SlackWebhookNotifier) Send(event types.InteractionEvent) error {
	jsonBody, err := wh.Payload(event)
	if err != nil {
		lg().Error("error marshaling JSON", "err", err)
		return err
	}

	return webhook.WebHookPost(wh.Endpoint(), jsonBody)
}
