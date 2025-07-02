package ftp

import (
	"github.com/defektive/xodbox/pkg/types"
	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/fclairamb/go-log/slog"
	"github.com/spf13/afero"
)

type Handler struct {
	name            string
	Listener        string
	dispatchChannel chan types.InteractionEvent
	//app             types.App
}

func NewHandler(handlerConfig map[string]string) types.Handler {

	listener := handlerConfig["listener"]

	return &Handler{
		name:     "FTP",
		Listener: listener,
	}
}

func (h Handler) Name() string {
	return h.name
}

func (h Handler) Start(app types.App, eventChan chan types.InteractionEvent) error {

	h.dispatchChannel = eventChan

	lg().Info("Starting FTP Server", "listener", h.Listener)
	afs := afero.NewMemMapFs()
	err := afs.MkdirAll("pizza/garbage/lunch", 0777)
	if err != nil {
		lg().Error("failed to create pizza directory", "error", err)
	}

	srv := ftpserver.NewFtpServer(&SimpleServerDriver{
		Debug: true,
		fs:    afero.NewBasePathFs(afs, "pizza/"),
		Settings: &ftpserver.Settings{
			DefaultTransferType: ftpserver.TransferTypeBinary,
			ListenAddr:          h.Listener,
		},
	})

	logger := slog.NewWrap(lg())
	srv.Logger = logger

	return srv.ListenAndServe()
}
