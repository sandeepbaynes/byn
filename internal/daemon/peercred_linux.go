//go:build linux

package daemon

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// peerCredFromFD returns the effective UID and PID of the peer connected
// via the given Unix-socket fd, using SO_PEERCRED.
func peerCredFromFD(fd int) (uint32, int, error) {
	ucred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, 0, fmt.Errorf("daemon: SO_PEERCRED: %w", err)
	}
	return ucred.Uid, int(ucred.Pid), nil
}
