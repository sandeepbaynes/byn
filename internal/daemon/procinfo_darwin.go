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
