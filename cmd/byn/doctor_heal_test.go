package main

import (
	"errors"
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
