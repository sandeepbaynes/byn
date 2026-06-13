//go:build linux

package privsep

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// SetUndumpable clears the process "dumpable" flag via prctl(PR_SET_DUMPABLE, 0).
//
// This is a defense-in-depth memory-hardening step on top of the load-bearing
// different-UID separation. With dumpable=0 the kernel:
//   - reparents the process's /proc/<pid>/ inodes (mem, environ, maps, fd, …)
//     to root:root, so a SAME-UID peer can no longer read them (closing the
//     same-UID residual the UID boundary leaves open between two _byn-exec
//     children, or between two _byn processes);
//   - disables core dumps for the process, so a crash can't spill the held
//     vault key or injected secrets to disk.
//
// It does NOT defend against root or CAP_SYS_PTRACE — root re-acquires access
// regardless. The honest ceiling (spec §2) is unchanged.
//
// Lowering one's own dumpable flag never requires privilege, so this succeeds
// for the unprivileged daemon and exec child alike.
func SetUndumpable() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE, 0): %w", err)
	}
	return nil
}
