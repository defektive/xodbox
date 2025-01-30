package app_log

import (
	"github.com/defektive/xodbox/pkg/xlog"
	"log/slog"
)

var pkgLogger *slog.Logger

func lg() *slog.Logger {
	if pkgLogger == nil {
		pkgLogger = xlog.Get()
	}
	return pkgLogger
}
