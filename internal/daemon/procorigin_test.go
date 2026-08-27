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
	if !sharesOriginFn(os.Getpid(), origin) {
		t.Errorf("sharesOrigin(self, parent) = false, want true")
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
	if !sharesOriginFn(cmd.Process.Pid, origin) {
		t.Errorf("sharesOrigin(child, our parent) = false, want true")
	}
}

func TestSharesOriginRejectsStrangers(t *testing.T) {
	origin := callerOriginFn(os.Getpid())
	if !origin.ok() {
		t.Skip("no usable parent origin in this environment")
	}
	// pid 1 is nobody's descendant but its own; it must not match.
	if sharesOriginFn(1, origin) {
		t.Errorf("sharesOrigin(1, our parent) = true, want false")
	}
	// Same PID, wrong start time — a recycled PID must not inherit the grant.
	recycled := procRef{PID: origin.PID, Start: origin.Start + 1}
	if sharesOriginFn(os.Getpid(), recycled) {
		t.Errorf("sharesOrigin with a mismatched start time = true, want false")
	}
	// An origin byn could not pin down grants nothing.
	if sharesOriginFn(os.Getpid(), procRef{PID: origin.PID}) {
		t.Errorf("sharesOrigin with a zero start time = true, want false")
	}
	if sharesOriginFn(os.Getpid(), procRef{}) {
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
