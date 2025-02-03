package slack

import (
	"encoding/json"
	"fmt"
	"github.com/defektive/xodbox/pkg/app/types"
	"github.com/defektive/xodbox/pkg/notifiers/webhook"
)

type POSTData struct {
	Channel   string `json:"channel"`
	Username  string `json:"username"`
	IconEmoji string `json:"icon_emoji"`
	Text      string `json:"text"`
}

type Notifier struct {
	*webhook.Notifier
	Channel string
	User    string
	Icon    string
}

func NewNotifier(notifierConfig map[string]string) types.Notifier {
	// be sure to update the _index.md file if you change stuff here
	url := notifierConfig["url"]
	channel := notifierConfig["channel"]
	user := notifierConfig["author"]
	icon := notifierConfig["author_image"]
	filter := notifierConfig["filter"]

	return &Notifier{
		Notifier: webhook.NewWebhookNotifier(url, filter),
		Channel:  channel,
		User:     user,
		Icon:     icon,
	}
}

func (wh *Notifier) Name() string {
	return "slack"
}

func (wh *Notifier) Payload(e types.InteractionEvent) ([]byte, error) {
	postBody := POSTData{
		Channel:   wh.Channel,
		Username:  wh.User,
		IconEmoji: wh.Icon,
		Text:      fmt.Sprintf("%s\n```%s\n```", e.Details(), e.Data()),
	}

	return json.Marshal(postBody)
}

func (wh *Notifier) Send(event types.InteractionEvent) error {
	if webhook.FilterMatches(wh.Filter(), event.Data()) {
		jsonBody, err := wh.Payload(event)
		if err != nil {
			lg().Error("error marshaling JSON", "err", err)
			return err
		}

		return webhook.SendPost(wh.URL, jsonBody)
	}

	return nil
}
