package ftp

import (
	"context"
	"strings"
	"sync"

	"github.com/defektive/xodbox/pkg/types"
	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"
)

type Handler struct {
	name            string
	ServerName      string
	Listener        string
	dispatchChannel chan types.InteractionEvent
	FakeDirTree     []string

	//app             types.App

	mu     sync.Mutex
	server *ftpserver.FtpServer
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
	srv.Logger = lg()

	h.mu.Lock()
	h.server = srv
	h.mu.Unlock()

	return srv.ListenAndServe()
}

// Stop tells the underlying *ftpserver.FtpServer to stop accepting
// new connections. ctx is currently advisory — ftpserverlib's Stop()
// does not accept a deadline; in-flight clients drain on their own.
// Safe to call before Start or multiple times.
func (h *Handler) Stop(ctx context.Context) error {
	h.mu.Lock()
	srv := h.server
	h.server = nil
	h.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Stop()
}

func (h *Handler) DispatchEvent(action Action, remoteAddr string) {
	e := NewEvent(remoteAddr, action)
	h.dispatchChannel <- e
}

func getAFS(dirsToCreate []string) afero.Fs {
	afs := afero.NewMemMapFs()

	for _, dir := range dirsToCreate {
		if err := afs.MkdirAll(dir, 0750); err != nil {
			lg().Warn("could not seed fake dir on memfs", "dir", dir, "err", err)
		}
	}

	return afs
}
