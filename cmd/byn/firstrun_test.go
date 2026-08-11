package main

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// Creating a vault is a real side effect, and a script that names the wrong
// vault must get an error rather than a brand-new empty one it did not ask for.
// Nothing here may create anything without a person on the other end.
func TestOfferVaultInit_RefusesWithoutAPerson(t *testing.T) {
	// jsonMode is the agent contract: never prompt, never act on a guess.
	if offerVaultInit(&ipc.Client{}, "somevault", true) {
		t.Error("created a vault in --json mode, where byn must never prompt")
	}
	// Tests do not run with a terminal on stdin, so this also covers the
	// piped/redirected case an agent actually hits.
	if offerVaultInit(&ipc.Client{}, "somevault", false) {
		t.Error("created a vault with no terminal to ask a person at")
	}
}

func TestIsNotInitErr(t *testing.T) {
	if !isNotInitErr(&ipc.ErrResponse{Code: ipc.CodeNotInit}) {
		t.Error("not_init reply not recognized")
	}
	if isNotInitErr(&ipc.ErrResponse{Code: ipc.CodeLocked}) {
		t.Error("a locked vault is not a missing one — it must not trigger creation")
	}
	if isNotInitErr(nil) {
		t.Error("nil is not an error")
	}
}

// A recovery hint that does not recover is worse than none: it spends the
// reader's trust before the real answer arrives. Under a service user
// `byn start` refuses and names a different command, so the first message has
// to be the one that works.
func TestDaemonDownRemedy(t *testing.T) {
	cmd, note := daemonDownRemedy(true)
	if cmd != "sudo byn restart" {
		t.Errorf("provisioned: cmd = %q, want the command that actually works", cmd)
	}
	if note == "" {
		t.Error("provisioned: no explanation for why root is needed")
	}
	if cmd, _ := daemonDownRemedy(false); cmd != "byn start" {
		t.Errorf("unprovisioned: cmd = %q, want byn start", cmd)
	}
}

// A daemon that failed to start is usually gone in milliseconds. Noticing that
// is what makes a generous readiness window affordable: without it, every real
// failure would wait out the full timeout before saying anything.
func TestWaitForSocketPID_FailsFastOnDeadChild(t *testing.T) {
	// A pid that cannot be running: reaped children are gone immediately.
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run true: %v", err)
	}
	dead := cmd.Process.Pid

	start := time.Now()
	if waitForSocketPID(t.TempDir(), dead, 20*time.Second) {
		t.Fatal("reported ready with no daemon at all")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("waited %s for a dead child; should give up as soon as it is gone", elapsed)
	}
}

// With no child to watch, the poller must still respect its deadline rather
// than hanging.
func TestWaitForSocketPID_HonoursDeadlineWithoutAChild(t *testing.T) {
	start := time.Now()
	if waitForSocketPID(t.TempDir(), 0, 300*time.Millisecond) {
		t.Fatal("reported ready with no daemon")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("overran its deadline by a lot: %s", elapsed)
	}
}

func TestProcessAlive(t *testing.T) {
	if !processAlive(os.Getpid()) {
		t.Error("this process reports itself dead")
	}
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run true: %v", err)
	}
	if processAlive(cmd.Process.Pid) {
		t.Error("a reaped process reports alive")
	}
}
