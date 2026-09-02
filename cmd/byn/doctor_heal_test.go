package main

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

// brokenHealEnv: provisioned, helper present, but root-owned data dir + daemon
// down — the exact post-`sudo byn start` mess repair must heal.
func brokenHealEnv() healEnv {
	return healEnv{
		provisioned: func() bool { return true },
		exists:      func(string) bool { return true },
		fileUID:     func(string) (int, bool) { return 0, true }, // root-owned → ownership FAILS
		bynUID:      func() (int, bool) { return 77, true },
		daemonUp:    func() bool { return false }, // down → daemon-running FAILS
		dataDir:     "/data",
		helperPath:  "/helper",
	}
}

// healthyHealEnv: everything OK — repair must be a no-op.
func healthyHealEnv() healEnv {
	e := brokenHealEnv()
	e.fileUID = func(string) (int, bool) { return 77, true } // owned by _byn
	e.daemonUp = func() bool { return true }                 // up
	return e
}

func TestDiagnoseHeal_NotProvisioned(t *testing.T) {
	// privsep is opt-in: a non-provisioned byn is the valid default, so doctor
	// reports a single INFORMATIONAL (OK) check — it must not fail.
	e := healEnv{provisioned: func() bool { return false }}
	cs := diagnoseHeal(e)
	if len(cs) != 1 || !cs[0].OK {
		t.Fatalf("not-provisioned: want one informational (OK) check, got %+v", cs)
	}
}

func TestDiagnoseHeal_Healthy(t *testing.T) {
	e := healEnv{
		provisioned: func() bool { return true },
		exists:      func(string) bool { return true },
		fileUID:     func(string) (int, bool) { return 77, true },
		bynUID:      func() (int, bool) { return 77, true },
		daemonUp:    func() bool { return true },
		dataDir:     "/data",
		helperPath:  "/helper",
	}
	for _, c := range diagnoseHeal(e) {
		if !c.OK {
			t.Errorf("healthy env: check %q failed: %s", c.Name, c.Detail)
		}
	}
}

func TestDiagnoseHeal_BrokenState(t *testing.T) {
	// Daemon down, helper missing, data dir owned by root (uid 0) not _byn (77),
	// and a stale socket present — the exact post-`sudo byn start` mess.
	exists := func(p string) bool { return strings.HasSuffix(p, "daemon.sock") } // helper missing; socket present
	e := healEnv{
		provisioned: func() bool { return true },
		exists:      exists,
		fileUID:     func(string) (int, bool) { return 0, true }, // root-owned
		bynUID:      func() (int, bool) { return 77, true },
		daemonUp:    func() bool { return false },
		dataDir:     "/data",
		helperPath:  "/helper",
	}
	byName := map[string]healCheck{}
	for _, c := range diagnoseHeal(e) {
		byName[c.Name] = c
	}
	for _, name := range []string{
		"spawn helper installed", "daemon running",
		"data dir owned by " + privsep.DaemonUser, "no stale socket",
	} {
		if c, present := byName[name]; !present || c.OK {
			t.Errorf("check %q: present=%v ok=%v — expected a present, FAILING check", name, present, c.OK)
		}
	}
}

func TestRepairHeal_ChownsAndRestarts(t *testing.T) {
	oldSleep := healSleep
	healSleep = func(time.Duration) {} // don't actually wait for the daemon
	t.Cleanup(func() { healSleep = oldSleep })

	var ran []string
	run := func(cmd string, args ...string) error {
		ran = append(ran, cmd+" "+strings.Join(args, " "))
		// Service appears already gone so the privsep reload poll exits fast.
		if cmd == "launchctl" && len(args) > 0 && args[0] == "print" {
			return errors.New("not loaded")
		}
		return nil
	}
	actions := repairHeal(brokenHealEnv(), run)
	joined := strings.Join(ran, "\n")
	if !strings.Contains(joined, "chown -R "+privsep.DaemonUser+":"+privsep.DaemonUser+" /data") {
		t.Errorf("repair must chown the data dir back to %s; ran:\n%s", privsep.DaemonUser, joined)
	}
	// Assert the reload via the returned action (platform-agnostic — the raw
	// command is `launchctl bootstrap` on macOS, `systemctl restart` on Linux).
	reloaded := false
	for _, a := range actions {
		if strings.Contains(a, "reloaded") {
			reloaded = true
		}
	}
	if !reloaded {
		t.Errorf("repair must reload the service for a down daemon; actions=%v ran:\n%s", actions, joined)
	}
	if len(actions) < 2 {
		t.Errorf("expected chown + reload actions, got %v", actions)
	}
}

// TestRepairHeal_NothingWhenHealthy: a healthy daemon must NOT be chowned or
// restarted — repair only touches FAILING checks. (Regression: --repair used to
// reload a healthy daemon every run, then falsely report it down mid-startup.)
func TestRepairHeal_NothingWhenHealthy(t *testing.T) {
	called := false
	run := func(string, ...string) error { called = true; return nil }
	actions := repairHeal(healthyHealEnv(), run)
	if called {
		t.Error("repair ran a command on a healthy env — it must be a no-op")
	}
	if len(actions) != 0 {
		t.Errorf("expected no actions for a healthy env, got %v", actions)
	}
}

// macOSHealEnv is a provisioned macOS-shaped machine: the daemon socket lives
// INSIDE the data dir, which is what makes the dir's mode load-bearing.
func macOSHealEnv(mode os.FileMode) healEnv {
	e := healthyHealEnv()
	e.fileMode = func(string) (os.FileMode, bool) { return mode, true }
	e.socketDir = func() string { return e.dataDir } // socket inside the data dir
	return e
}

func TestDiagnoseHeal_DataDirNotTraversable(t *testing.T) {
	// The regression this exists for: a relocate leaves the data dir 0700, the
	// daemon is up and bound, and the owner cannot traverse to its socket. The
	// daemon then reports as down, so the check that must fire is the one about
	// the MODE — without it the only advice is "restart", which fixes nothing.
	e := macOSHealEnv(0o700)
	e.daemonUp = func() bool { return false } // unreachable, though the daemon runs

	var found *healCheck
	for i, c := range diagnoseHeal(e) {
		if c.Name == "data dir traversable by owner" {
			found = &diagnoseHeal(e)[i]
		}
	}
	if found == nil {
		t.Fatal("0700 data dir with the socket inside it: want a traversability check, got none")
	}
	if found.OK {
		t.Error("0700 data dir: check passed, but the owner cannot reach the socket")
	}
	if !strings.Contains(found.Detail, "0711") {
		t.Errorf("detail should name the expected mode, got %q", found.Detail)
	}
}

func TestDiagnoseHeal_DataDirTraversable(t *testing.T) {
	// 0711 is the provisioned mode: traverse, no listing. It must not be reported.
	for _, mode := range []os.FileMode{0o711, 0o755} {
		for _, c := range diagnoseHeal(macOSHealEnv(mode)) {
			if c.Name == "data dir traversable by owner" {
				t.Errorf("mode %#o is traversable; want no check, got %+v", mode, c)
			}
		}
	}
}

func TestDiagnoseHeal_DataDirModeNotCheckedWhenSocketElsewhere(t *testing.T) {
	// Linux keeps the socket in a separate /run/byn, so a 0700 state dir locks
	// nobody out. Reporting it there would be a fault the user cannot act on.
	e := macOSHealEnv(0o700)
	e.socketDir = func() string { return "/run/byn" }
	for _, c := range diagnoseHeal(e) {
		if c.Name == "data dir traversable by owner" {
			t.Errorf("socket outside the data dir: mode is irrelevant, got %+v", c)
		}
	}
}

func TestRepairHeal_ChmodsDataDirAndSkipsRestart(t *testing.T) {
	// Repair must put the mode back FIRST and then notice the daemon was healthy
	// all along, rather than bouncing a service that was never the problem.
	e := macOSHealEnv(0o700)
	reachable := false
	e.daemonUp = func() bool { return reachable }

	var cmds []string
	run := func(name string, args ...string) error {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		if name == "chmod" {
			reachable = true // the door opens; the daemon was up the whole time
		}
		return nil
	}
	healSleep = func(time.Duration) {}

	done := repairHeal(e, run)

	var chmodded bool
	for _, c := range cmds {
		if strings.HasPrefix(c, "chmod 0711 /data") {
			chmodded = true
		}
		if strings.Contains(c, "launchctl") || strings.Contains(c, "systemctl") {
			t.Errorf("repair restarted the service after the mode fix made it reachable: %q", c)
		}
	}
	if !chmodded {
		t.Errorf("want a chmod 0711 on the data dir, got %v", cmds)
	}
	if !strings.Contains(strings.Join(done, "; "), "owner-traversable") {
		t.Errorf("repair should report the mode fix, got %v", done)
	}
}
