package smb

import (
	"fmt"
	"net"
	"sync"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/util"
)

// dbMu serialises writes to the SQLite handle. The pure-Go driver does not
// love concurrent writers and each accepted connection runs in its own
// goroutine.
var dbMu sync.Mutex

// persistAuth stores a captured NetNTLMv2 credential as an Interaction so
// it survives restarts and shows up alongside other handler activity in
// the DB / web view. The hashcat mode 5600 line is kept in Data; the
// DOMAIN\User the client authenticated as rides in RequestTarget for quick
// scanning. Only called when the handler's persist knob is enabled.
func persistAuth(c net.Conn, info *AuthInfo, hash string) {
	hostname, portNum := util.GetHostAndPortFromRemoteAddr(c.RemoteAddr().String())

	i := &model.Interaction{
		RemoteAddr:    hostname,
		RemotePort:    fmt.Sprintf("%d", portNum),
		Handler:       "smb",
		Protocol:      "smb",
		RequestType:   "Auth",
		RequestTarget: info.Account(),
		Data:          []byte(hash),
	}

	dbMu.Lock()
	defer dbMu.Unlock()
	if tx := model.DB().Create(i); tx.Error != nil {
		lg().Debug("failed to persist smb interaction", "err", tx.Error, "remote", hostname)
	}
}
