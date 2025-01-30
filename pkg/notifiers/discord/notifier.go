package discord

import (
	"encoding/json"
	"fmt"
	"github.com/defektive/xodbox/pkg/app/types"
	"github.com/defektive/xodbox/pkg/notifiers/webhook"
)

type DiscordWebhookPost struct {
	Username  string `json:"username"`
	AvatarURL string `json:"avatar_url"`
	Content   string `json:"content"`
}

type DiscordWebhookNotifier struct {
	types.Notifier
	User string
	Icon string
}

func NewDiscordWebhookNotifier(url, user, icon string) types.Notifier {
	return &DiscordWebhookNotifier{
		Notifier: webhook.NewWebhookNotifier(url),
		User:     user,
		Icon:     icon,
	}
}

func (wh *DiscordWebhookNotifier) Payload(e types.InteractionEvent) ([]byte, error) {
	postBody := DiscordWebhookPost{
		Username:  wh.User,
		AvatarURL: wh.Icon,
		Content:   fmt.Sprintf("%s\n```%s\n```", e.Details(), e.Data()),
	}

	return json.Marshal(postBody)
}

func (wh *DiscordWebhookNotifier) Send(event types.InteractionEvent) error {
	jsonBody, err := wh.Payload(event)
	if err != nil {
		lg().Error("error marshaling JSON", "err", err)
		return err
	}

	return webhook.WebHookPost(wh.Endpoint(), jsonBody)
}
