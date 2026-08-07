package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

const killPgrpFlag = "--kill-pgrp"

// killPgrpRequested reports whether the helper was invoked in kill-pgrp mode
// and returns the PGID to kill.
func killPgrpRequested(args []string) (pgid int, ok bool) {
	for i, a := range args {
		if a == killPgrpFlag && i+1 < len(args) {
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n <= 1 {
				return 0, false
			}
			return n, true
		}
	}
	return 0, false
}

// killPgrpMain drops to _byn-exec and sends SIGTERM to the given process group.
// Used by byn kill to clean up all _byn-exec descendants of a privsep exec
// wrapper in one shot. The wrapper uses Setpgid(0,0) so PGID = wrapper PID;
// all _byn-exec children (pnpm, node, tsx, …) share that PGID and die here.
// The owner-UID wrapper is also in the group but _byn-exec cannot signal it
// (EPERM); byn kill sends it SIGTERM separately after returning.
func killPgrpMain(pgid int) {
	uid, gid, err := readTargetIDs()
	if err != nil {
		fatal("reading target ids: %v", err)
	}
	if uid <= 0 || gid <= 0 {
		fatal("config has non-positive uid/gid (%d/%d)", uid, gid)
	}

	if err := dropTo(uid, gid); err != nil {
		fatal("dropping privileges: %v", err)
	}

	// Send SIGTERM to the process group. The caller can't do this directly
	// because the group members are _byn-exec (different UID). As _byn-exec
	// we can. The owner-UID wrapper in the group gets EPERM; since at least
	// one member is signalled, kill(2) returns 0.
	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "byn-exec-helper: kill(-pgrp %d, SIGTERM): %v\n", pgid, err)
		os.Exit(1)
	}
}
