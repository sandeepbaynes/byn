package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

func TestDiagnoseHeal_NotProvisioned(t *testing.T) {
	e := healEnv{provisioned: func() bool { return false }}
	cs := diagnoseHeal(e)
	if len(cs) != 1 || cs[0].Name != "privsep provisioned" || cs[0].OK {
		t.Fatalf("not-provisioned: want one failing 'privsep provisioned' check, got %+v", cs)
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
	var ran []string
	run := func(cmd string, args ...string) error {
		ran = append(ran, cmd+" "+strings.Join(args, " "))
		// Make the service appear already gone so the reload poll exits without
		// any real sleep (svcSleep lives in the privsep package).
		if cmd == "launchctl" && len(args) > 0 && args[0] == "print" {
			return errors.New("not loaded")
		}
		return nil
	}
	actions := repairHeal(healEnv{dataDir: "/data"}, run)
	joined := strings.Join(ran, "\n")
	if !strings.Contains(joined, "chown -R "+privsep.DaemonUser+":"+privsep.DaemonUser+" /data") {
		t.Errorf("repair must chown the data dir back to %s; ran:\n%s", privsep.DaemonUser, joined)
	}
	if len(actions) == 0 {
		t.Error("repair should report the actions it took")
	}
}
