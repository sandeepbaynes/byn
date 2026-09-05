package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
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
	//
	// ESRCH is NOT a failure. An orphan outlives its wrapper, and the wrapper
	// was the group leader, so by the time anyone wants to kill the orphan
	// there is no group left to signal — the overwhelmingly common case for
	// this call. Reporting it as an error made `byn kill` print a scary line
	// about a process it had not even tried to signal yet, immediately above a
	// success message. Nothing to signal is simply nothing to do.
	//
	// EPERM is the same non-event from the other side. kill(2) on a group only
	// fails with EPERM when NO member could be signalled, and after the drop
	// this process can signal exactly the service user's processes — so EPERM
	// means the group holds none of them (a --no-privsep job, whose children
	// are all the owner's). Those are byn kill's to signal directly, and it
	// does, so the line this used to print sat above "stopped" for a job that
	// was stopped fine.
	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.EPERM) {
			return
		}
		fmt.Fprintf(os.Stderr, "byn-exec-helper: kill(-pgrp %d, SIGTERM): %v\n", pgid, err)
		os.Exit(1)
	}
}

// ---- kill by pid -------------------------------------------------------

const (
	killPidsFlag   = "--kill-pids"
	killSignalFlag = "--signal"
	// maxKillPids bounds one invocation. The list comes from a process-table
	// walk, so a few hundred is already extreme; the cap exists so a malformed
	// or hostile argv cannot turn one call into an unbounded signal storm.
	maxKillPids = 4096
)

// killPidsRequested parses `--kill-pids <csv> [--signal TERM|KILL]`.
//
// Every pid must be >= 2, and that check is load-bearing rather than tidiness:
// kill(2) reads 0 as "every process in my group", -1 as "every process I am
// permitted to signal", and negatives as process groups. Passing any of those
// through would turn a targeted cleanup into a machine-wide one, so the parse
// refuses them outright instead of trusting the caller.
func killPidsRequested(args []string) (pids []int, sig syscall.Signal, ok bool) {
	sig = syscall.SIGTERM
	var csv string
	for i, a := range args {
		switch a {
		case killPidsFlag:
			if i+1 < len(args) {
				csv = args[i+1]
			}
		case killSignalFlag:
			if i+1 >= len(args) {
				return nil, 0, false
			}
			// A fixed vocabulary, not a numeric passthrough: these two are the
			// only signals the cleanup path has any business sending.
			switch args[i+1] {
			case "TERM":
				sig = syscall.SIGTERM
			case "KILL":
				sig = syscall.SIGKILL
			default:
				return nil, 0, false
			}
		}
	}
	if csv == "" {
		return nil, 0, false
	}
	for _, f := range strings.Split(csv, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil || n < 2 {
			return nil, 0, false
		}
		pids = append(pids, n)
	}
	if len(pids) == 0 || len(pids) > maxKillPids {
		return nil, 0, false
	}
	return pids, sig, true
}

// killPidsMain drops to _byn-exec and signals each pid individually.
//
// It exists because the process-group route cannot reach an orphan: the group
// died with the wrapper that led it. The owner cannot signal these either —
// they belong to another uid, so kill(2) is EPERM — which left `byn kill`
// unable to touch precisely the processes people needed it for.
//
// After the drop this process is _byn-exec, so the kernel already confines it
// to that account's own processes; a pid naming anything else fails with EPERM
// exactly as it would for any other unprivileged caller. That is the same
// authority --kill-pgrp has always had, addressed one process at a time.
//
// Per-pid outcomes go to stdout as "ok <pid>" / "err <pid> <reason>" so the
// caller can report what actually happened rather than assuming.
func killPidsMain(pids []int, sig syscall.Signal) {
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
	for _, pid := range pids {
		if kerr := syscall.Kill(pid, sig); kerr != nil {
			fmt.Printf("err %d %v\n", pid, kerr)
			continue
		}
		fmt.Printf("ok %d\n", pid)
	}
}
