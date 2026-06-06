//go:build darwin

package daemon

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// peerCredFromFD returns the effective UID and PID of the peer connected
// via the given Unix-socket fd. On macOS the UID comes from LOCAL_PEERCRED
// (Xucred) and the PID from LOCAL_PEERPID (best-effort).
func peerCredFromFD(fd int) (uint32, int, error) {
	xuc, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, 0, fmt.Errorf("daemon: LOCAL_PEERCRED: %w", err)
	}
	pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		pid = 0 // PID is best-effort; UID enforcement is the load-bearing check
	}
	return xuc.Uid, pid, nil
}
