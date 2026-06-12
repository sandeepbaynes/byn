//go:build darwin

package daemon

import (
	"bytes"

	"golang.org/x/sys/unix"
)

// procInfo returns the process name (comm) and parent PID for pid, via
// sysctl kern.proc.pid. Best-effort: returns zero values on any error.
func procInfo(pid int) (comm string, ppid int) {
	if pid <= 0 {
		return "", 0
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil {
		return "", 0
	}
	c := kp.Proc.P_comm[:]
	if i := bytes.IndexByte(c, 0); i >= 0 {
		c = c[:i]
	}
	return string(c), int(kp.Eproc.Ppid)
}

// NOTE: a same-UID process could in principle call TIOCSCTTY to acquire
// another process's controlling terminal (same-UID ceiling). This is
// accepted residual risk: the Unix socket is already mode 0600 and
// uid-gated at the connection layer, so the ttyDev binding is a
// convenience scope, not a security boundary.
//
// peerTTYDev returns the controlling terminal device number for pid.
// Returns 0 if the process has no controlling terminal (daemon/portal callers,
// or lookup failure) — callers treat 0 as "uid-only binding".
func peerTTYDev(pid int) int32 {
	if pid <= 0 {
		return 0
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil {
		return 0
	}
	// Tdev == -1 (int32 wraps to 0xFFFFFFFF) means "no controlling terminal"
	// on Darwin. Normalise to 0.
	if kp.Eproc.Tdev == -1 {
		return 0
	}
	return kp.Eproc.Tdev
}
