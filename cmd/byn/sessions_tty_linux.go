//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// ttyRdev returns the controlling terminal device number by reading
// /proc/self/stat field 7 (tty_nr). This matches the value the daemon
// reads via peerTTYDev for the CLI's own PID, ensuring CLI and daemon
// compute the same device number. Returns 0 if no controlling terminal
// or on any error.
//
// NOTE: a same-UID process could in principle call TIOCSCTTY to acquire
// another process's controlling terminal. This is accepted residual risk:
// the Unix socket is already mode 0600, so a same-UID attacker can
// connect directly; the ttyDev check is a convenience binding, not a
// security boundary.
func ttyRdev() int32 {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0
	}
	s := string(b)
	// /proc/self/stat: "pid (comm) state ppid pgrp session tty_nr ..."
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
