//go:build darwin

package daemon

import "golang.org/x/sys/unix"

// procStartTime returns pid's start time in microseconds since the epoch, via
// sysctl kern.proc.pid — the same lookup the rest of the darwin proc helpers
// use. Paired with the PID it names one process across PID reuse.
//
// Returns ok=false on any error, which callers treat as "no usable identity".
func procStartTime(pid int) (uint64, bool) {
	if pid <= 0 {
		return 0, false
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil {
		return 0, false
	}
	sec, usec := kp.Proc.P_starttime.Sec, kp.Proc.P_starttime.Usec
	if sec <= 0 {
		return 0, false
	}
	return uint64(sec)*1_000_000 + uint64(usec), true //#nosec G115 -- both are non-negative here
}
