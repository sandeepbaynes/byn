//go:build linux

package daemon

import (
	"os"
	"strconv"
	"strings"
)

// procStartTime returns the kernel's start-time counter for pid, read from
// /proc/<pid>/stat. It is the clock-tick count since boot at which the process
// started, which the kernel never reissues — so (pid, start) names one process
// for the lifetime of the boot even after the PID is recycled.
//
// Returns ok=false on any error, which callers treat as "no usable identity".
func procStartTime(pid int) (uint64, bool) {
	if pid <= 0 {
		return 0, false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false
	}
	// /proc/<pid>/stat: "pid (comm) state ppid ...". comm can contain spaces
	// and parens, so fields are counted after the LAST ')'.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, false
	}
	// Fields after ')': state(0) ppid(1) pgrp(2) session(3) tty_nr(4) tpgid(5)
	// flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10) utime(11) stime(12)
	// cutime(13) cstime(14) priority(15) nice(16) num_threads(17)
	// itrealvalue(18) starttime(19).
	const startTimeField = 19
	f := strings.Fields(s[i+1:])
	if len(f) <= startTimeField {
		return 0, false
	}
	v, err := strconv.ParseUint(f[startTimeField], 10, 64)
	if err != nil || v == 0 {
		return 0, false
	}
	return v, true
}
