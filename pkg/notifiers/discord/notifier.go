package discord

import (
	"encoding/json"
	"fmt"
	"github.com/defektive/xodbox/pkg/notifiers/webhook"
	"github.com/defektive/xodbox/pkg/types"
)

type POSTData struct {
	Username  string `json:"username"`
	AvatarURL string `json:"avatar_url"`
	Content   string `json:"content"`
}

type Notifier struct {
	*webhook.Notifier
	User string
	Icon string
}

func NewNotifier(notifierConfig map[string]string) types.Notifier {
	// be sure to update the _index.md file if you change stuff here
	url := notifierConfig["url"]
	user := notifierConfig["author"]
	icon := notifierConfig["author_image"]
	filter := notifierConfig["filter"]

	return &Notifier{
		Notifier: webhook.NewNotifier(url, filter),
		User:     user,
		Icon:     icon,
	}
}

func (wh *Notifier) Name() string {
	return "discord"
}

func (wh *Notifier) Payload(e types.InteractionEvent) ([]byte, error) {
	postBody := POSTData{
		Username:  wh.User,
		AvatarURL: wh.Icon,
		Content:   fmt.Sprintf("%s\n```%s\n```", e.Details(), e.Data()),
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
