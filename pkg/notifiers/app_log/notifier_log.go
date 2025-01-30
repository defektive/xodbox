package app_log

import (
	"github.com/defektive/xodbox/pkg/app/types"
)

type LogNotifier struct {
}

func NewLogNotifier() types.Notifier {
	return &LogNotifier{}
}

func (wh *LogNotifier) Name() string {
	return "LogNotifier"
}

func (wh *LogNotifier) Endpoint() string {
	return "file"
}

func (wh *LogNotifier) Payload(e types.InteractionEvent) ([]byte, error) {
	return []byte{}, nil
}

func (wh *LogNotifier) Send(e types.InteractionEvent) error {
	lg().Info("InteractionEvent received", "details", e.Details())
	return nil
}
