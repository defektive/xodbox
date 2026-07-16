package discord

import (
	"encoding/json"
	"strings"

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

// discordMaxContent is the hard limit Discord imposes on the content field.
const discordMaxContent = 2000

func truncateContent(s string, max int) string {
	const suffix = "\n…\n```"
	cut := s[:max-len(suffix)]
	if strings.Count(cut, "```")%2 == 1 {
		return cut + suffix
	}
	return cut + "\n…"
}

func (wh *Notifier) Payload(e types.InteractionEvent) ([]byte, error) {
	content := webhook.ChatText(e)
	if len(content) > discordMaxContent {
		content = truncateContent(content, discordMaxContent)
	}
	postBody := POSTData{
		Username:  wh.User,
		AvatarURL: wh.Icon,
		Content:   content,
	}

	return json.Marshal(postBody)
}

func (wh *Notifier) Send(event types.InteractionEvent) error {
	if webhook.ShouldSend(wh.Filter(), event) {
		jsonBody, err := wh.Payload(event)
		if err != nil {
			lg().Error("error marshaling JSON", "err", err)
			return err
		}

		return webhook.SendPost(wh.URL, jsonBody)
	}

	return nil
}
