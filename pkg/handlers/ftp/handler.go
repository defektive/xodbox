package ftp

import (
	"github.com/defektive/xodbox/pkg/types"
	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/fclairamb/go-log/slog"
	"github.com/spf13/afero"
	"strings"
)

type Handler struct {
	name            string
	ServerName      string
	Listener        string
	dispatchChannel chan types.InteractionEvent
	FakeDirTree     []string

	//app             types.App
}

func NewHandler(handlerConfig map[string]string) types.Handler {

	listener := handlerConfig["listener"]
	serverName, ok := handlerConfig["server_name"]
	if !ok {
		serverName = "FTP Server"
	}
	fakeDirTree, ok := handlerConfig["fake_dir_tree"]
	if !ok {
		fakeDirTree = "test/old/fake,test/new/fake"
	}

	fakeDirs := strings.Split(fakeDirTree, ",")

	return &Handler{
		name:        "FTP",
		ServerName:  serverName,
		FakeDirTree: fakeDirs,
		Listener:    listener,
	}
}

func (h *Handler) Name() string {
	return h.name
}

func (h *Handler) Start(app types.App, eventChan chan types.InteractionEvent) error {
	h.dispatchChannel = eventChan
	lg().Info("Starting FTP Server", "ServerName", h.ServerName, "listener", h.Listener)

	afs := getAFS(h.FakeDirTree)
	simpleDriver := &SimpleServerDriver{
		Handler:    h,
		ServerName: h.ServerName,
		Debug:      true,
		fs:         afero.NewBasePathFs(afs, "./"),
		Settings: &ftpserver.Settings{
			DefaultTransferType: ftpserver.TransferTypeBinary,
			ListenAddr:          h.Listener,
		},
	}

	srv := ftpserver.NewFtpServer(simpleDriver)
	logger := slog.NewWrap(lg())
	srv.Logger = logger

	return srv.ListenAndServe()
}

func (h *Handler) DispatchEvent(action Action, remoteAddr string) {
	e := NewEvent(remoteAddr, action)
	h.dispatchChannel <- e
}

func getAFS(dirsToCreate []string) afero.Fs {
	afs := afero.NewMemMapFs()

	for _, dir := range dirsToCreate {
		afs.MkdirAll(dir, 0777)
	}

	return afs
}
