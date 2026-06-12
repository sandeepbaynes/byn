//go:build linux

package daemon

import (
	"os"
	"strconv"
	"strings"
)

// NOTE: a same-UID process could in principle call TIOCSCTTY to acquire
// another process's controlling terminal (same-UID ceiling). This is
// accepted residual risk: the Unix socket is already mode 0600 and
// uid-gated at the connection layer, so the ttyDev binding is a
// convenience scope, not a security boundary.
//
// peerTTYDev returns the controlling terminal device number for pid from
// /proc/<pid>/stat field tty_nr. Returns 0 on any error or if no controlling
// terminal is present (tty_nr == 0).
func peerTTYDev(pid int) int32 {
	if pid <= 0 {
		return 0
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	s := string(b)
	// /proc/<pid>/stat: "pid (comm) state ppid pgrp session tty_nr ..."
	// comm can contain spaces/parens, so split after the LAST ')'.
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	// Fields after ')': state(0), ppid(1), pgrp(2), session(3), tty_nr(4)
	fields := strings.Fields(s[i+1:])
	if len(fields) < 5 {
		return 0
	}
	v, err := strconv.ParseInt(fields[4], 10, 32)
	if err != nil {
		return 0
	}
	return int32(v) //nolint:gosec // tty_nr is a kernel device number, not a secret
}

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
