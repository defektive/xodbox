package app_log

import (
	"regexp"

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
	return "InteractionEvent received", []any{"details", e.Details()}
}

func (wh *Notifier) Send(e types.InteractionEvent) error {
	if !wh.filter.MatchString(e.FilterString()) {
		return nil
	}
	msg, args := wh.Payload(e)
	lg().Info(msg, args...)
	return nil
}
