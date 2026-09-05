package daemon

import (
	"os"
	"os/exec"
	"testing"
)

// These run against the real process tree on purpose. The end-to-end daemon
// tests stub the origin lookups (one test process cannot produce two different
// origins), so without these the actual walk — the thing that decides whether
// an agent gets its own variable back — would never be executed by the suite.

func TestCallerOriginIsTheParent(t *testing.T) {
	got := callerOriginFn(os.Getpid())
	if !got.ok() {
		t.Fatalf("callerOrigin(self) = %+v, want a usable origin", got)
	}
	if got.PID != os.Getppid() {
		t.Errorf("origin PID = %d, want the parent %d", got.PID, os.Getppid())
	}
}

func TestSharesOriginMatchesOwnAncestor(t *testing.T) {
	origin := callerOriginFn(os.Getpid())
	if !origin.ok() {
		t.Skip("no usable parent origin in this environment")
	}
	if !sharesAncestryFn(os.Getpid(), []procRef{origin}) {
		t.Errorf("a caller must match its own parent")
	}

	// A grandchild still shares it: an agent's tool call runs byn a level or
	// two down, which is the whole case this exists for.
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot spawn a child here: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	if !sharesAncestryFn(cmd.Process.Pid, []procRef{origin}) {
		t.Errorf("a grandchild must match an ancestor")
	}
}

func TestSharesOriginRejectsStrangers(t *testing.T) {
	origin := callerOriginFn(os.Getpid())
	if !origin.ok() {
		t.Skip("no usable parent origin in this environment")
	}
	// pid 1 is nobody's descendant but its own; it must not match.
	if sharesAncestryFn(1, []procRef{origin}) {
		t.Errorf("pid 1 is nobody's descendant but its own; it must not match")
	}
	// Same PID, wrong start time — a recycled PID must not inherit the grant.
	recycled := procRef{PID: origin.PID, Start: origin.Start + 1}
	if sharesAncestryFn(os.Getpid(), []procRef{recycled}) {
		t.Errorf("sharesOrigin with a mismatched start time = true, want false")
	}
	// An origin byn could not pin down grants nothing.
	if sharesAncestryFn(os.Getpid(), []procRef{{PID: origin.PID}}) {
		t.Errorf("sharesOrigin with a zero start time = true, want false")
	}
	if sharesAncestryFn(os.Getpid(), []procRef{{}}) {
		t.Errorf("sharesOrigin with an empty origin = true, want false")
	}
}

func TestProcStartTimeIsStableAndDistinguishes(t *testing.T) {
	a, ok := procStartTime(os.Getpid())
	if !ok || a == 0 {
		t.Fatalf("procStartTime(self) = %d, ok=%v; want a non-zero value", a, ok)
	}
	b, _ := procStartTime(os.Getpid())
	if a != b {
		t.Errorf("procStartTime not stable across calls: %d then %d", a, b)
	}
	if _, ok := procStartTime(0); ok {
		t.Errorf("procStartTime(0) reported ok, want not ok")
	}
}

// The shape the agent using byn measured, and the one that defeated counting
// hops: one command plain, the next wrapped in `timeout bash -c`.
//
//	plain:   byn ← bash ← agent
//	wrapped: byn ← bash ← timeout ← bash ← agent
//
// A fixed depth reaches the agent in the first and misses it in the second, so
// the two never recognise each other — and the agent could store a value it
// could never read back. Identity has to be what a process IS, not how far up
// it sits.
func TestIdentitySeesThroughWrappers(t *testing.T) {
	// This process stands in for the agent. A plain child, and a child behind
	// two layers of wrapper, must resolve to the same identity: us.
	plain := exec.Command("sleep", "30")
	if err := plain.Start(); err != nil {
		t.Skipf("cannot spawn: %v", err)
	}
	t.Cleanup(func() { _ = plain.Process.Kill(); _, _ = plain.Process.Wait() })

	// Two wrapper layers, spelled portably. This used to run `timeout`, which
	// is GNU coreutils and simply absent on macOS — so the whole test skipped
	// there, and the wrapper-transparency rule that decides who an action is
	// ATTRIBUTED to had no coverage at all on that platform. Nested shells make
	// the same shape out of a tool every POSIX system has, and `sh` is in
	// transientWrappers exactly as `timeout` is.
	wrapped := exec.Command("sh", "-c", "sh -c 'sleep 30'")
	if err := wrapped.Start(); err != nil {
		t.Skipf("cannot spawn wrapped: %v", err)
	}
	t.Cleanup(func() { _ = wrapped.Process.Kill(); _, _ = wrapped.Process.Wait() })

	me := os.Getpid()
	plainID := callerIdentity(plain.Process.Pid)
	if !plainID.ok() {
		t.Skip("no usable identity in this environment")
	}
	if plainID.PID != me {
		t.Errorf("plain child resolved to pid %d, want this process (%d) — the shell above it should be walked past",
			plainID.PID, me)
	}
	// The wrapped child is `timeout` itself here; its identity must still be us,
	// reached past timeout and the shell it runs.
	recorded := callerAncestryFn(wrapped.Process.Pid)
	if len(recorded) == 0 {
		t.Fatal("no identity recorded for a wrapped caller")
	}
	if !sharesAncestryFn(plain.Process.Pid, recorded) {
		t.Fatalf("a wrapped caller and a plain one under the same agent were not recognised as the same; wrapped=%v plainID=%v",
			recorded, plainID)
	}
}

// Two commands run in DIFFERENT short-lived shells under one agent must count
// as the same caller.
//
// This is the shape every agent harness has: each tool call gets its own shell,
// so the process that ran `byn put` is gone by the time `byn exec` runs. Byn
// used to record only that shell, which meant the exemption expired at the end
// of every tool call — the workflow it exists for, broken, while every test
// passed because each did its put and its exec inside one shell.
func TestAncestryMatchesAcrossSiblingShells(t *testing.T) {
	// Two children of THIS process stand in for two tool-call shells; this
	// process stands in for the agent that spawned both.
	spawn := func() *exec.Cmd {
		t.Helper()
		cmd := exec.Command("sleep", "30")
		if err := cmd.Start(); err != nil {
			t.Skipf("cannot spawn a child here: %v", err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		})
		return cmd
	}
	first, second := spawn(), spawn()

	recorded := callerAncestryFn(first.Process.Pid)
	if len(recorded) == 0 {
		t.Skip("no usable ancestry in this environment")
	}
	if !sharesAncestryFn(second.Process.Pid, recorded) {
		t.Fatalf("two shells under one agent were not recognised as the same caller; recorded=%v", recorded)
	}
	// The recorded identity must be the agent, not the shell that happened to
	// launch this one command — a shell dies with the tool call, and matching on
	// it is what made the exemption expire at the end of every call.
	if recorded[0].PID == first.Process.Pid {
		t.Error("identity resolved to the calling process itself")
	}
	if recorded[0].PID != os.Getpid() {
		t.Errorf("identity resolved to pid %d, want the agent above the shells (%d)",
			recorded[0].PID, os.Getpid())
	}
}

// The chain must stay short. Reaching the desktop session would make every
// process on the machine share an ancestor, and the check would mean nothing.
func TestAncestryIsBounded(t *testing.T) {
	chain := callerAncestryFn(os.Getpid())
	if len(chain) > 1 {
		t.Errorf("identity has %d entries, want exactly one", len(chain))
	}
	for _, p := range chain {
		if p.PID <= 1 {
			t.Errorf("ancestry contains pid %d; everything descends from init", p.PID)
		}
	}
}

func TestSharesAncestryRejectsNothing(t *testing.T) {
	if sharesAncestryFn(os.Getpid(), nil) {
		t.Error("an empty recorded ancestry must grant nothing")
	}
	if sharesAncestryFn(os.Getpid(), []procRef{{PID: 999999, Start: 1}}) {
		t.Error("an unrelated ancestry must not match")
	}
	if sharesAncestryFn(0, callerAncestryFn(os.Getpid())) {
		t.Error("a caller byn cannot identify must not match")
	}
}
