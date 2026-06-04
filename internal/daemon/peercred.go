package daemon

import (
	"errors"
	"fmt"
	"net"
)

// ErrNotUnix is returned when peer-credential inspection is requested
// on a non-Unix-socket connection.
var ErrNotUnix = errors.New("daemon: connection is not a Unix socket")

// peerCred returns the effective UID and PID of the peer process
// connected via a Unix socket. Implementation lives in
// peercred_darwin.go / peercred_linux.go.
func peerCred(conn net.Conn) (uint32, int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, ErrNotUnix
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, fmt.Errorf("daemon: SyscallConn: %w", err)
	}
	var uid uint32
	var pid int
	var inner error
	if err := raw.Control(func(fd uintptr) {
		uid, pid, inner = peerCredFromFD(int(fd))
	}); err != nil {
		return 0, 0, fmt.Errorf("daemon: control: %w", err)
	}
	if inner != nil {
		return 0, 0, inner
	}
	return uid, pid, nil
}

// closeAcceptedConn is a thin wrapper so the dispatcher can ignore
// the error consistently — these errors are usually peer-closed-too-
// fast and not worth surfacing.
func closeAcceptedConn(c net.Conn) {
	if c == nil {
		return
	}
	_ = c.Close()
}
