package main

// cmd_kill.go stops byn exec jobs.
//
// The hard case, and the one this is built around, is the ORPHAN: a child whose
// `byn exec` wrapper is gone. Three separate things made byn report success
// while killing nothing there, and each is addressed below —
//
//  1. The process-group route cannot reach it. The wrapper led the group, so
//     once it dies kill(-pgrp) is ESRCH and there is nothing left to signal.
//  2. The owner cannot signal it. It runs as the exec service user, so a direct
//     kill(2) from the CLI is EPERM. The return value was discarded.
//  3. Nothing checked. "sent SIGTERM to N" was printed unconditionally, so a
//     signal that was never delivered read exactly like one that was.
//
// The result was a command that left ports held and offered no recovery short
// of `sudo pkill` — the one outcome privilege separation is supposed to avoid.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

// procEntry is the minimum a signal decision needs: who a process is, who its
// parent is, and which account it runs as. Filled per-platform (see
// procsnapshot_*.go) so the tree walk and the signalling below are shared.
type procEntry struct {
	pid  int
	ppid int
	uid  int
	pgid int
}

// How long a job gets to shut down cleanly before byn stops asking.
//
// SIGTERM is the right first signal — a dev server flushes and closes its
// listener — but a process that ignores it must not be allowed to keep the port
// for ever, which is the state that sent people to `sudo pkill`. So the grace
// period is bounded and then escalates. The values are deliberately not
// configurable: this is a wait for a process to die, not a policy anyone tunes.
const (
	killGrace     = 5 * time.Second
	killHardGrace = 3 * time.Second
	killPoll      = 100 * time.Millisecond
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
		exitCode := 0
		for _, j := range jobs {
			if !stopExecProc(j.pid) {
				exitCode = exitErr
			}
		}
		return exitCode
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
		if !stopExecProc(pid) {
			exitCode = exitErr
		}
	}
	return exitCode
}

// killPgrpViaHelper runs byn-exec-helper --kill-pgrp <pgid> to send SIGTERM
// to all _byn-exec processes in the wrapper's process group. Non-fatal: if
// the helper is not installed or returns an error, the per-pid pass below
// covers the same processes one at a time.
func killPgrpViaHelper(pgid int) {
	helperPath := helperIfInstalled()
	if helperPath == "" {
		return
	}
	cmd := exec.Command(helperPath, "--kill-pgrp", strconv.Itoa(pgid)) //nolint:gosec
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

// helperIfInstalled returns the setuid helper's path, or "" when it is absent.
func helperIfInstalled() string {
	helperPath := privsep.HelperDestPath()
	if helperPath == "" {
		return ""
	}
	if _, err := os.Stat(helperPath); err != nil {
		return ""
	}
	return helperPath
}

// descendantsOf returns root plus every process beneath it, nearest first.
//
// Direct children are not enough: the process actually holding the port is
// typically a grandchild (pnpm → node → tsx), so a sweep that stopped at depth
// one named the wrong pid in its output and left the listener running.
//
// The visited set is not defensive clutter. A process table is a snapshot taken
// while pids are being recycled, so the parent links in it are not guaranteed to
// form a tree; without the guard a reused pid can close a cycle and hang the walk.
func descendantsOf(root int, procs []procEntry) []int {
	children := map[int][]int{}
	for _, p := range procs {
		children[p.ppid] = append(children[p.ppid], p.pid)
	}
	visited := map[int]bool{root: true}
	out := []int{root}
	for i := 0; i < len(out); i++ {
		kids := children[out[i]]
		sort.Ints(kids)
		for _, k := range kids {
			if visited[k] {
				continue
			}
			visited[k] = true
			out = append(out, k)
		}
	}
	return out
}

// isGroupLeader reports whether pid leads the process group of the same number.
//
// Only a leader's pid is safe to hand to a group kill: kill(-N) means "group N",
// not "the group containing N", so passing the pid of a process that merely
// belongs to some other group signals whatever group happens to bear that
// number. An unknown pid answers false — if byn cannot see the process table it
// must not guess about a signal that reaches more than one process.
func isGroupLeader(pid int, procs []procEntry) bool {
	for _, p := range procs {
		if p.pid == pid {
			return p.pgid == pid
		}
	}
	return false
}

// signalPIDs sends sig to each pid, routing each one by who owns it: the
// caller's own processes directly, everything else through the setuid helper,
// which drops to the exec service user and can reach them.
//
// Returns the pids it could not signal, with the reason — the information the
// old code threw away.
func signalPIDs(pids []int, uidOf map[int]int, sig syscall.Signal) map[int]string {
	failed := map[int]string{}
	me := os.Getuid()
	var viaHelper []int

	for _, pid := range pids {
		uid, known := uidOf[pid]
		if known && uid != me {
			viaHelper = append(viaHelper, pid)
			continue
		}
		if err := syscall.Kill(pid, sig); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				continue // already gone: not a failure
			}
			// An unknown owner that we cannot signal is very likely the service
			// user's, so give the helper a chance rather than reporting defeat.
			if !known && errors.Is(err, syscall.EPERM) {
				viaHelper = append(viaHelper, pid)
				continue
			}
			failed[pid] = err.Error()
		}
	}

	if len(viaHelper) == 0 {
		return failed
	}
	helperPath := helperIfInstalled()
	if helperPath == "" {
		for _, pid := range viaHelper {
			failed[pid] = "runs as " + privsep.ExecUser + " and the byn exec helper is not installed"
		}
		return failed
	}
	name := "TERM"
	if sig == syscall.SIGKILL {
		name = "KILL"
	}
	strs := make([]string, len(viaHelper))
	for i, p := range viaHelper {
		strs[i] = strconv.Itoa(p)
	}
	out, err := exec.Command(helperPath, //nolint:gosec // operator-installed helper at a fixed path
		"--kill-pids", strings.Join(strs, ","), "--signal", name).Output()
	if err != nil {
		for _, pid := range viaHelper {
			failed[pid] = "byn exec helper: " + err.Error()
		}
		return failed
	}
	// The helper reports one line per pid: "ok <pid>" or "err <pid> <reason>".
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "err" {
			continue
		}
		pid, cerr := strconv.Atoi(f[1])
		if cerr != nil {
			continue
		}
		reason := strings.Join(f[2:], " ")
		if strings.Contains(reason, "no such process") {
			continue // it died between the snapshot and the signal
		}
		failed[pid] = reason
	}
	return failed
}

// waitGone polls until every pid has exited or the deadline passes, returning
// those still alive.
func waitGone(pids []int, budget time.Duration) []int {
	deadline := time.Now().Add(budget)
	for {
		var alive []int
		for _, pid := range pids {
			if processAlive(pid) {
				alive = append(alive, pid)
			}
		}
		if len(alive) == 0 || !time.Now().Before(deadline) {
			return alive
		}
		time.Sleep(killPoll)
	}
}

// stopExecProc stops a byn exec job and every process under it, and reports
// what actually happened. Returns whether the whole tree is gone.
func stopExecProc(pid int) bool {
	procs := snapshotProcs()
	uidOf := make(map[int]int, len(procs))
	for _, p := range procs {
		uidOf[p.pid] = p.uid
	}
	targets := descendantsOf(pid, procs)

	// The group sweep first, but ONLY when this process actually leads the group
	// its pid names. Where the wrapper is alive that is true — it calls
	// Setpgid(0,0), so PGID == PID — and one call takes the whole job.
	//
	// For an orphan it is false, and sending the signal anyway is not merely
	// useless: pids are recycled, so a dead wrapper's pid can be reused as the
	// leader of an UNRELATED group, and byn would signal somebody else's
	// processes. The orphan case is covered below, per pid, which is the only
	// way to reach it — its own group died with the wrapper that led it.
	if isGroupLeader(pid, procs) {
		killPgrpViaHelper(pid)
	}

	failed := signalPIDs(targets, uidOf, syscall.SIGTERM)
	alive := waitGone(targets, killGrace)

	if len(alive) > 0 {
		// Escalate. A process that sat through SIGTERM is not going to release
		// the port on its own, and leaving it is what made a stale dev server
		// block every later run.
		hardFailed := signalPIDs(alive, uidOf, syscall.SIGKILL)
		alive = waitGone(alive, killHardGrace)
		for p, reason := range hardFailed {
			failed[p] = reason
		}
	}

	stopped := len(targets) - len(alive)
	if len(alive) == 0 {
		fmt.Printf("stopped %d (%d process%s)\n", pid, stopped, plural(stopped))
		return true
	}

	sort.Ints(alive)
	fmt.Fprintf(os.Stderr, "%s byn kill: %d process%s under %d survived\n",
		boldRed("Error:"), len(alive), plural(len(alive)), pid)
	for _, p := range alive {
		if reason, ok := failed[p]; ok {
			fmt.Fprintf(os.Stderr, "  %d — %s\n", p, reason)
			continue
		}
		fmt.Fprintf(os.Stderr, "  %d — ignored SIGTERM and SIGKILL\n", p)
	}
	fmt.Fprintf(os.Stderr, "  %s\n", dim("run `byn doctor` to check the exec helper is installed and current"))
	return false
}

// plural renders the "es" of "process/processes".
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "es"
}
