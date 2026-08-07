package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

func runKill(args []string) int {
	killAll := false
	var targetPIDs []int

	for _, a := range args {
		switch a {
		case "--all":
			killAll = true
		default:
			pid, err := strconv.Atoi(a)
			if err != nil || pid <= 0 {
				fmt.Fprintf(os.Stderr, "byn kill: invalid PID %q\n", a)
				return exitErr
			}
			targetPIDs = append(targetPIDs, pid)
		}
	}

	if !killAll && len(targetPIDs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: byn kill [--all] [<pid>...]")
		fmt.Fprintln(os.Stderr, "       Run 'byn ps' to list byn exec process IDs.")
		return exitErr
	}

	jobs := findBynExecProcs()

	if killAll {
		if len(jobs) == 0 {
			fmt.Fprintln(os.Stderr, "no byn exec processes found")
			return 0
		}
		for _, j := range jobs {
			stopExecProc(j.pid)
		}
		return 0
	}

	// Build a set of valid byn exec PIDs for validation so we don't
	// inadvertently SIGTERM unrelated processes.
	bynPIDs := make(map[int]struct{}, len(jobs))
	for _, j := range jobs {
		bynPIDs[j.pid] = struct{}{}
	}

	exitCode := 0
	for _, pid := range targetPIDs {
		if _, ok := bynPIDs[pid]; !ok {
			fmt.Fprintf(os.Stderr, "byn kill: %d is not a byn exec process (run 'byn ps' to list them)\n", pid)
			exitCode = exitErr
			continue
		}
		stopExecProc(pid)
	}
	return exitCode
}

// killPgrpViaHelper runs byn-exec-helper --kill-pgrp <pgid> to send SIGTERM
// to all _byn-exec processes in the wrapper's process group. Non-fatal: if
// the helper is not installed or returns an error, pdeathsig still catches
// the direct child when the wrapper exits.
func killPgrpViaHelper(pgid int) {
	helperPath := privsep.HelperDestPath()
	if helperPath == "" {
		return
	}
	if _, err := os.Stat(helperPath); err != nil {
		return // helper not installed
	}
	cmd := exec.Command(helperPath, "--kill-pgrp", strconv.Itoa(pgid)) //nolint:gosec
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

// stopExecProc kills all _byn-exec descendants in the wrapper's process group,
// then sends SIGTERM to direct children and the wrapper itself. The wrapper
// uses Setpgid(0,0) so its PGID equals its own PID; byn-exec-helper drops to
// _byn-exec and can signal the group members the owner UID cannot reach.
func stopExecProc(pid int) {
	killPgrpViaHelper(pid)

	children := findChildren(pid)
	for _, child := range children {
		_ = syscall.Kill(child, syscall.SIGTERM)
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)

	msg := fmt.Sprintf("sent SIGTERM to %d", pid)
	if len(children) > 0 {
		strs := make([]string, len(children))
		for i, c := range children {
			strs[i] = strconv.Itoa(c)
		}
		msg += fmt.Sprintf(" (children: %s)", strings.Join(strs, ", "))
	}
	fmt.Println(msg)
}
