//go:build darwin

package daemon

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// xucredVersion is the LOCAL_PEERCRED Xucred layout version this code
// understands. macOS defines XUCRED_VERSION as 0 (bsd/sys/ucred.h); x/sys/unix
// does not export it. Validating it is belt-and-suspenders: the UID field is
// only meaningful for a recognized layout, so a mismatch means we should refuse
// rather than trust a UID we may be misreading from an unexpected structure.
const xucredVersion = 0

// peerCredFromFD returns the effective UID and PID of the peer connected
// via the given Unix-socket fd. On macOS the UID comes from LOCAL_PEERCRED
// (Xucred) and the PID from LOCAL_PEERPID (best-effort).
func peerCredFromFD(fd int) (uint32, int, error) {
	xuc, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, 0, fmt.Errorf("daemon: LOCAL_PEERCRED: %w", err)
	}
	if xuc.Version != xucredVersion {
		return 0, 0, fmt.Errorf("daemon: LOCAL_PEERCRED returned unexpected Xucred version %d (want %d)", xuc.Version, xucredVersion)
	}
	pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		pid = 0 // PID is best-effort; UID enforcement is the load-bearing check
	}
	return xuc.Uid, pid, nil
}
