package app_log

import (
	"regexp"

	"github.com/defektive/xodbox/pkg/notifiers/webhook"
	"github.com/defektive/xodbox/pkg/types"
)

type Notifier struct {
	filter *regexp.Regexp
}

func NewNotifier(notifierConfig map[string]string) types.Notifier {
	filter := notifierConfig["filter"]
	if filter == "" {
		filter = ".*"
	}

	return &Notifier{
		filter: regexp.MustCompile(filter),
	}
}

func (wh *Notifier) Filter() *regexp.Regexp {
	return wh.filter
}

func (wh *Notifier) Name() string {
	return "app_log"
}

func (wh *Notifier) Payload(e types.InteractionEvent) (string, []any) {
	args := []any{"details", e.Details()}
	if cp, ok := e.(types.CurlProvider); ok {
		if curl := cp.CurlCommand(); curl != "" {
			args = append(args, "curl", curl)
		}
	}
	return "InteractionEvent received", args
}

func (wh *Notifier) Send(e types.InteractionEvent) error {
	if !webhook.ShouldSend(wh.filter, e) {
		return nil
	}
	msg, args := wh.Payload(e)
	lg().Info(msg, args...)
	return nil
}
