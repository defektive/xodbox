package app_log

import (
	"github.com/defektive/xodbox/pkg/types"
	"regexp"
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

func (wh *Notifier) Endpoint() string {
	return "file"
}

func (wh *Notifier) Payload(e types.InteractionEvent) ([]byte, error) {
	return []byte{}, nil
}

func (wh *Notifier) Send(e types.InteractionEvent) error {
	lg().Info("InteractionEvent received", "details", e.Details())
	return nil
}
