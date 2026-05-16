package cmd

import (
	"log/slog"

	"github.com/defektive/xodbox/pkg/xlog"
)

var pkgLogger *slog.Logger

func lg() *slog.Logger {
	if pkgLogger == nil {
		pkgLogger = xlog.Get()
	}
	return pkgLogger
}
