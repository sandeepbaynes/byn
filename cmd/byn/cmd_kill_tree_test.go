package main

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestDescendantsOf_WalksTheWholeTree(t *testing.T) {
	// pnpm (10) -> node (20) -> tsx (30): the port is held by the grandchild,
	// which is exactly the process a direct-children sweep missed.
	procs := []procEntry{
		{pid: 10, ppid: 1, uid: 451},
		{pid: 20, ppid: 10, uid: 451},
		{pid: 30, ppid: 20, uid: 451},
		{pid: 99, ppid: 1, uid: 501}, // unrelated: must not be swept in
	}
	got := descendantsOf(10, procs)
	if len(got) != 3 {
		t.Fatalf("got %v, want the job and both descendants", got)
	}
	if got[0] != 10 {
		t.Errorf("the named pid must come first, got %v", got)
	}
	seen := map[int]bool{}
	for _, p := range got {
		seen[p] = true
	}
	for _, want := range []int{10, 20, 30} {
		if !seen[want] {
			t.Errorf("pid %d missing from %v", want, got)
		}
	}
	if seen[99] {
		t.Errorf("unrelated pid 99 swept in: %v", got)
	}
}

func TestDescendantsOf_SurvivesACycle(t *testing.T) {
	// A process table is a snapshot taken while pids are recycled, so the
	// parent links in it need not form a tree. Without the visited set this
	// hangs rather than failing, so the test is the guard.
	procs := []procEntry{
		{pid: 10, ppid: 20},
		{pid: 20, ppid: 10},
	}
	// A hang here fails the test by timeout, which is the point: the assertion
	// is that this returns at all.
	got := descendantsOf(10, procs)
	if len(got) != 2 {
		t.Fatalf("got %v, want both pids once each", got)
	}
}

func TestDescendantsOf_LoneProcess(t *testing.T) {
	got := descendantsOf(7, []procEntry{{pid: 7, ppid: 1}})
	if len(got) != 1 || got[0] != 7 {
		t.Fatalf("got %v, want just [7]", got)
	}
}

func TestDescendantsOf_UnknownPidStillTargetsIt(t *testing.T) {
	// The snapshot can be empty (an unsupported platform); the named pid must
	// still be signalled rather than silently dropped.
	got := descendantsOf(42, nil)
	if len(got) != 1 || got[0] != 42 {
		t.Fatalf("got %v, want [42]", got)
	}
}

func TestSignalPIDs_ReportsFailureInsteadOfClaimingSuccess(t *testing.T) {
	// pid 1 is init: a normal user cannot signal it, so this exercises the path
	// that used to be discarded with `_ =` and reported as "sent SIGTERM".
	if os.Getuid() == 0 {
		t.Skip("running as root: init is signalable")
	}
	// uid 0 is not this process's uid, so without a helper installed the pid
	// must come back as a failure with a reason — never as a success.
	failed := signalPIDs([]int{1}, map[int]int{1: 0}, syscall.SIGTERM)
	if len(failed) != 1 {
		t.Fatalf("expected pid 1 to be reported unsignalable, got %v", failed)
	}
	if failed[1] == "" {
		t.Error("a failure must carry a reason")
	}
}

func TestSignalPIDs_AlreadyGoneIsNotAFailure(t *testing.T) {
	// A process that exited between the table snapshot and the signal is the
	// normal outcome of killing a tree — the parent dies and takes the child
	// with it — so ESRCH must not be reported as a survivor.
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a probe process: %v", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Wait() // reaped: the pid is now gone

	failed := signalPIDs([]int{pid}, map[int]int{pid: os.Getuid()}, syscall.SIGTERM)
	if len(failed) != 0 {
		t.Fatalf("an already-exited process was reported as a failure: %v", failed)
	}
}

func TestPlural(t *testing.T) {
	if plural(1) != "" || plural(0) != "es" || plural(2) != "es" {
		t.Fatal("plural")
	}
}

// kill(-N) means "process group N", not "the group containing N". Handing it
// the pid of a process that merely belongs to some other group signals whatever
// group happens to bear that number — and pids are recycled, so a dead
// wrapper's pid can come back as an unrelated group's leader.
func TestIsGroupLeader(t *testing.T) {
	procs := []procEntry{
		{pid: 100, ppid: 1, pgid: 100},   // a wrapper: leads its own group
		{pid: 101, ppid: 100, pgid: 100}, // a child in that group
		{pid: 200, ppid: 1, pgid: 150},   // an orphan: its leader is gone
	}
	if !isGroupLeader(100, procs) {
		t.Error("a process whose pgid equals its pid leads the group")
	}
	if isGroupLeader(101, procs) {
		t.Error("a group MEMBER must not be treated as its leader")
	}
	if isGroupLeader(200, procs) {
		t.Error("an orphan does not lead group 200; signalling it could hit an unrelated group")
	}
	// Unknown pid: byn cannot see the table, so it must not guess about a
	// signal that reaches more than one process.
	if isGroupLeader(999, procs) {
		t.Error("an unknown pid must not be assumed to be a group leader")
	}
}
