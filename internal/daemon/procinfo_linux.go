//go:build linux

package daemon

import (
	"os"
	"strconv"
	"strings"
)

// procInfo returns the process name (comm) and parent PID for pid, read
// from /proc. Best-effort: returns zero values on any error.
func procInfo(pid int) (comm string, ppid int) {
	if pid <= 0 {
		return "", 0
	}
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm"); err == nil {
		comm = strings.TrimSpace(string(b))
	}
	// /proc/<pid>/stat: "pid (comm) state ppid ...". comm may contain
	// spaces/parens, so split after the LAST ')'.
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		s := string(b)
		if i := strings.LastIndexByte(s, ')'); i >= 0 && i+1 < len(s) {
			f := strings.Fields(s[i+1:]) // [state, ppid, ...]
			if len(f) >= 2 {
				ppid, _ = strconv.Atoi(f[1])
			}
		}
	}
	return comm, ppid
}
