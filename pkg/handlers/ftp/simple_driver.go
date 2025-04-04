package ftp

import (
	"crypto/tls"
	"errors"
	"github.com/defektive/xodbox/pkg/handlers/smtp"
	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type tlsVerificationReply int8

//type TLSRequirement int8

const (
	// tls certificate is ok but a password is required too
	tlsVerificationOK tlsVerificationReply = iota
	// tls certificate verification failed, the client will be disconnected
	tlsVerificationFailed
	// tls certificate is ok and no password is required
	tlsVerificationAuthenticated
)

const (
	authUser    = "test"
	authPass    = "test"
	authUserID  = 1000
	authGroupID = 500
)

var errInvalidTLSCertificate = errors.New("invalid TLS certificate")

// SimpleServerDriver defines a minimal serverftp server driver
type SimpleServerDriver struct {
	Debug          bool // To display connection logs information
	TLS            bool
	CloseOnConnect bool // disconnect the client as soon as it connects

	Settings             *ftpserver.Settings // Settings
	fs                   afero.Fs
	clientMU             sync.Mutex
	Clients              []ftpserver.ClientContext
	TLSVerificationReply tlsVerificationReply
	errPassiveListener   error
	TLSRequirement       ftpserver.TLSRequirement
}

// SimpleClientDriver defines a minimal serverftp client driver
type SimpleClientDriver struct {
	afero.Fs
}

type testFile struct {
	afero.File
	errTransfer error
}

var (
	errFailClose   = errors.New("couldn't close")
	errFailWrite   = errors.New("couldn't write")
	errFailSeek    = errors.New("couldn't seek")
	errFailReaddir = errors.New("couldn't readdir")
	errFailOpen    = errors.New("couldn't open")
)

func (f *testFile) Read(out []byte) (int, error) {
	// simulating a slow reading allows us to test ABOR
	if strings.Contains(f.File.Name(), "delay-io") {
		time.Sleep(500 * time.Millisecond)
	}

	return f.File.Read(out)
}

func (f *testFile) Write(out []byte) (int, error) {
	if strings.Contains(f.File.Name(), "fail-to-write") {
		return 0, errFailWrite
	}

	// simulating a slow writing allows us to test ABOR
	if strings.Contains(f.File.Name(), "delay-io") {
		time.Sleep(500 * time.Millisecond)
	}

	return f.File.Write(out)
}

func (f *testFile) Close() error {
	if strings.Contains(f.File.Name(), "fail-to-close") {
		return errFailClose
	}

	return f.File.Close()
}

func (f *testFile) Seek(offset int64, whence int) (int64, error) {
	// by delaying the seek and sending a REST before the actual transfer
	// we can delay the opening of the transfer and then test an ABOR before
	// opening a transfer. I'm not sure if this can really happen but it is
	// better to be prepared for buggy clients too
	if strings.Contains(f.File.Name(), "delay-io") {
		time.Sleep(500 * time.Millisecond)
	}

	if strings.Contains(f.File.Name(), "fail-to-seek") {
		return 0, errFailSeek
	}

	return f.File.Seek(offset, whence)
}

func (f *testFile) Readdir(count int) ([]os.FileInfo, error) {
	log.Println("readdir file")
	if strings.Contains(f.File.Name(), "delay-io") {
		time.Sleep(500 * time.Millisecond)
	}

	if strings.Contains(f.File.Name(), "fail-to-readdir") {
		return nil, errFailReaddir
	}

	return f.File.Readdir(count)
}

// TransferError implements the FileTransferError interface
func (f *testFile) TransferError(err error) {
	f.errTransfer = err
}

// NewSimpleClientDriver creates a client driver
func NewSimpleClientDriver(server *SimpleServerDriver) *SimpleClientDriver {
	return &SimpleClientDriver{
		Fs: server.fs,
	}
}

func mustStopServer(server *ftpserver.FtpServer) {
	err := server.Stop()
	if err != nil {
		panic(err)
	}
}

var errConnectionNotAllowed = errors.New("connection not allowed")

// ClientConnected is the very first message people will see
func (driver *SimpleServerDriver) ClientConnected(cltContext ftpserver.ClientContext) (string, error) {
	driver.clientMU.Lock()
	defer driver.clientMU.Unlock()

	var err error

	if driver.CloseOnConnect {
		err = errConnectionNotAllowed
	}

	cltContext.SetDebug(driver.Debug)
	// we set the client id as extra data just for testing
	cltContext.SetExtra(cltContext.ID())
	driver.Clients = append(driver.Clients, cltContext)
	// This will remain the official name for now
	return "TEST Server", err
}

var errBadUserNameOrPassword = errors.New("bad username or password")

// AuthUser with authenticate users
func (driver *SimpleServerDriver) AuthUser(_ ftpserver.ClientContext, user, pass string) (ftpserver.ClientDriver, error) {
	if user == authUser && pass == authPass {
		clientdriver := NewSimpleClientDriver(driver)

		return clientdriver, nil
	} else if user == "nil" && pass == "nil" {
		// Definitely a bad behavior (but can be done on the driver side)
		return nil, nil //nolint:nilnil
	}

	return nil, errBadUserNameOrPassword
}

type MesssageDriver struct {
	SimpleServerDriver
}

// PostAuthMessage returns a message displayed after authentication
func (driver *MesssageDriver) PostAuthMessage(_ ftpserver.ClientContext, _ string, authErr error) string {
	if authErr != nil {
		return "You are not welcome here"
	}

	return "Welcome to the FTP Server"
}

// QuitMessage returns a goodbye message
func (driver *MesssageDriver) QuitMessage() string {
	return "Sayonara, bye bye!"
}

// ClientDisconnected is called when the user disconnects
func (driver *SimpleServerDriver) ClientDisconnected(cc ftpserver.ClientContext) {
	driver.clientMU.Lock()
	defer driver.clientMU.Unlock()

	for idx, client := range driver.Clients {
		if client.ID() == cc.ID() {
			lastIdx := len(driver.Clients) - 1
			driver.Clients[idx] = driver.Clients[lastIdx]
			driver.Clients[lastIdx] = nil
			driver.Clients = driver.Clients[:lastIdx]

			return
		}
	}
}

// GetClientsInfo returns info about the connected clients
func (driver *SimpleServerDriver) GetClientsInfo() map[uint32]interface{} {
	driver.clientMU.Lock()
	defer driver.clientMU.Unlock()

	info := make(map[uint32]interface{})

	for _, clientContext := range driver.Clients {
		ccInfo := make(map[string]interface{})

		ccInfo["localAddr"] = clientContext.LocalAddr()
		ccInfo["remoteAddr"] = clientContext.RemoteAddr()
		ccInfo["clientVersion"] = clientContext.GetClientVersion()
		ccInfo["path"] = clientContext.Path()
		ccInfo["hasTLSForControl"] = clientContext.HasTLSForControl()
		ccInfo["hasTLSForTransfers"] = clientContext.HasTLSForTransfers()
		ccInfo["lastCommand"] = clientContext.GetLastCommand()
		ccInfo["debug"] = clientContext.Debug()
		ccInfo["extra"] = clientContext.Extra()

		info[clientContext.ID()] = ccInfo
	}

	return info
}

var errNoClientConnected = errors.New("no client connected")

// DisconnectClient disconnect one of the connected clients
func (driver *SimpleServerDriver) DisconnectClient() error {
	driver.clientMU.Lock()
	defer driver.clientMU.Unlock()

	if len(driver.Clients) > 0 {
		return driver.Clients[0].Close()
	}

	return errNoClientConnected
}

// GetSettings fetches the basic server settings
func (driver *SimpleServerDriver) GetSettings() (*ftpserver.Settings, error) {
	return driver.Settings, nil
}

var errNoTLS = errors.New("TLS is not configured")

// GetTLSConfig fetches the TLS config
func (driver *SimpleServerDriver) GetTLSConfig() (*tls.Config, error) {
	if driver.TLS {
		ic := smtp.NewInsecureCert()
		config, err := ic.TLSConfig("pizza.com")
		if err != nil {
			return nil, err
		}

		return config, nil
	}

	return nil, errNoTLS
}

func (driver *SimpleServerDriver) PreAuthUser(cc ftpserver.ClientContext, _ string) error {
	return cc.SetTLSRequirement(driver.TLSRequirement)
}

func (driver *SimpleServerDriver) VerifyConnection(_ ftpserver.ClientContext, _ string,
	_ *tls.Conn,
) (ftpserver.ClientDriver, error) {
	switch driver.TLSVerificationReply {
	case tlsVerificationFailed:
		return nil, errInvalidTLSCertificate
	case tlsVerificationAuthenticated:
		clientdriver := NewSimpleClientDriver(driver)

		return clientdriver, nil
	case tlsVerificationOK:
		return nil, nil //nolint:nilnil
	}

	return nil, nil //nolint:nilnil
}

func (driver *SimpleServerDriver) WrapPassiveListener(listener net.Listener) (net.Listener, error) {
	if driver.errPassiveListener != nil {
		return nil, driver.errPassiveListener
	}

	return listener, nil
}

// OpenFile opens a file in 3 possible modes: read, write, appending write (use appropriate flags)
func (driver *SimpleClientDriver) OpenFile(path string, flag int, perm os.FileMode) (afero.File, error) {
	if strings.Contains(path, "fail-to-open") {
		return nil, errFailOpen
	}

	if strings.Contains(path, "quota-exceeded") {
		return nil, ftpserver.ErrStorageExceeded
	}

	if strings.Contains(path, "not-allowed") {
		return nil, ftpserver.ErrFileNameNotAllowed
	}

	file, err := driver.Fs.OpenFile(path, flag, perm)

	if err == nil {
		file = &testFile{File: file}
	}

	return file, err
}

func (driver *SimpleClientDriver) Open(name string) (afero.File, error) {
	if strings.Contains(name, "fail-to-open") {
		return nil, errFailOpen
	}

	log.Println("open file")
	file, err := driver.Fs.Open(name)

	if err == nil {
		file = &testFile{File: file}
	}

	return file, err
}

func (driver *SimpleClientDriver) Rename(oldname, newname string) error {
	if strings.Contains(newname, "not-allowed") {
		return ftpserver.ErrFileNameNotAllowed
	}

	return driver.Fs.Rename(oldname, newname)
}

var errTooMuchSpaceRequested = errors.New("you're requesting too much space")

func (driver *SimpleClientDriver) AllocateSpace(size int) error {
	if size < 1*1024*1024 {
		return nil
	}

	return errTooMuchSpaceRequested
}

var errAvblNotPermitted = errors.New("you're not allowed to request available space for this directory")

func (driver *SimpleClientDriver) GetAvailableSpace(dirName string) (int64, error) {
	if dirName == "/noavbl" {
		return 0, errAvblNotPermitted
	}

	return int64(123), nil
}

var (
	errInvalidChownUser  = errors.New("invalid chown on user")
	errInvalidChownGroup = errors.New("invalid chown on group")
)

func (driver *SimpleClientDriver) Chown(name string, uid int, gid int) error {
	if uid != 0 && uid != authUserID {
		return errInvalidChownUser
	}

	if gid != 0 && gid != authGroupID {
		return errInvalidChownGroup
	}

	_, err := driver.Fs.Stat(name)

	return err
}

var errSymlinkNotImplemented = errors.New("symlink not implemented")

func (driver *SimpleClientDriver) Symlink(oldname, newname string) error {
	if linker, ok := driver.Fs.(afero.Linker); ok {
		return linker.SymlinkIfPossible(oldname, newname)
	}

	return errSymlinkNotImplemented
}
