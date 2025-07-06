package main

import (
	"fmt"
	"github.com/creack/pty"
	"github.com/defektive/xodbox/pkg/util"
	"github.com/defektive/xodbox/pkg/xlog"
	"github.com/gliderlabs/ssh"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"os/exec"
)

// listener can be overridden at build time. defaults to :4444
var listener = ":2222"

// allowedCIDR can be overridden at build time. defaults to 0.0.0.0/0
var allowedCIDR = "0.0.0.0/0"

var logLevel = "NONE"
var pkgLogger *slog.Logger

var loglevels map[string]slog.Level = map[string]slog.Level{
	"NONE":                   10,
	slog.LevelInfo.String():  slog.LevelInfo,
	slog.LevelWarn.String():  slog.LevelWarn,
	slog.LevelError.String(): slog.LevelError,
	slog.LevelDebug.String(): slog.LevelDebug,
}

// lg internal log helper
func lg() *slog.Logger {
	if pkgLogger == nil {
		pkgLogger = xlog.Get()
	}
	return pkgLogger
}

func setWinsize(f *os.File, w, h int) {
	//syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
	//	uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func main() {
	if ll, ok := loglevels[logLevel]; ok {
		xlog.LogLevel(ll)
	}

	_, allowedNet, err := net.ParseCIDR(allowedCIDR)
	if err != nil {
		lg().Error("Error parsing allowed CIDR", "allowedCIDR", allowedCIDR, "err", err)
	}

	ssh.Handle(func(s ssh.Session) {

		host, _ := util.HostAndPortFromRemoteAddr(s.RemoteAddr().String())
		remoteIp := net.ParseIP(host)
		if !allowedNet.Contains(remoteIp) {
			// not allowed
			s.Exit(1)
			return
		}

		cmd := exec.Command(getCommandToExecute())
		ptyReq, winCh, isPty := s.Pty()
		if isPty {
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
			f, err := pty.Start(cmd)
			if err != nil {
				panic(err)
			}
			go func() {
				for win := range winCh {
					setWinsize(f, win.Width, win.Height)
				}
			}()
			go func() {
				i, err := io.Copy(f, s) // stdin
				lg().Debug("copy from socket to ssh (stdin)", "written", i, "err", err)

			}()
			i, err := io.Copy(s, f) // stdout
			lg().Debug("copy from ssh to socket (stdout)", "written", i, "err", err)

			if err := cmd.Wait(); err != nil {
				lg().Error("Command finished with error", "error", err)
			}
		} else {
			i, err := io.WriteString(s, "No PTY requested.\n")
			lg().Debug("no pty", "wrote", i, "err", err)
			s.Exit(1)
		}
	})

	lg().Info("starting ssh server", "listener", listener)
	log.Fatal(ssh.ListenAndServe(listener, nil))
}

func getCommandToExecute() string {

	cmds := []string{"zsh", "bash", "powershell", "cmd"}
	for _, cmd := range cmds {
		res, err := exec.LookPath(cmd)
		if err == nil {
			return res
		}
	}
	return "sh"
}
