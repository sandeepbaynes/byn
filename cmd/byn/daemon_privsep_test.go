package main

import (
	"errors"
	"testing"
)

// Tests must NEVER touch the real launchd/systemd service. Default the privsep
// probe to "not provisioned" so daemon-control tests take the owner-daemon path;
// tests that exercise the provisioned branches opt in via stubPrivsep (which
// also stubs the service calls, so no real launchctl/systemctl ever runs).
func init() { daemonProvisioned = func() bool { return false } }

// stubPrivsep installs deterministic seams for the privsep-aware daemon-control
// branches and restores them after the test. Returns counters for the service
// calls.
func stubPrivsep(t *testing.T, provisioned, reachable bool, restartErr, stopErr error) (restarts, stops *int) {
	t.Helper()
	oldProv, oldReach := daemonProvisioned, daemonReachableFn
	oldRestart, oldStop := restartServiceFn, stopServiceFn
	r, s := 0, 0
	daemonProvisioned = func() bool { return provisioned }
	daemonReachableFn = func(string) bool { return reachable }
	restartServiceFn = func() error { r++; return restartErr }
	stopServiceFn = func() error { s++; return stopErr }
	t.Cleanup(func() {
		daemonProvisioned, daemonReachableFn = oldProv, oldReach
		restartServiceFn, stopServiceFn = oldRestart, oldStop
	})
	return &r, &s
}

func TestStart_ProvisionedAndUp_ReportsRunning(t *testing.T) {
	stubPrivsep(t, true, true, nil, nil)
	if got := runDaemonStart(nil); got != exitOK {
		t.Fatalf("start (provisioned, up) = %d, want exitOK", got)
	}
}

func TestStart_ProvisionedAndDown_DelegatesNotSpawn(t *testing.T) {
	stubPrivsep(t, true, false, nil, nil)
	if got := runDaemonStart(nil); got != exitErr {
		t.Fatalf("start (provisioned, down) = %d, want exitErr (delegate message)", got)
	}
}

func TestRestart_Provisioned_CallsRestartService(t *testing.T) {
	restarts, _ := stubPrivsep(t, true, true, nil, nil)
	if got := runDaemonRestart(nil); got != exitOK {
		t.Fatalf("restart (provisioned) = %d, want exitOK", got)
	}
	if *restarts != 1 {
		t.Errorf("RestartService called %d times, want 1", *restarts)
	}
}

func TestRestart_Provisioned_ServiceErrorSurfaces(t *testing.T) {
	stubPrivsep(t, true, true, errors.New("boom"), nil)
	if got := runDaemonRestart(nil); got != exitErr {
		t.Fatalf("restart with service error = %d, want exitErr", got)
	}
}

func TestStop_Provisioned_CallsStopService(t *testing.T) {
	_, stops := stubPrivsep(t, true, true, nil, nil)
	if got := runDaemonStop(nil); got != exitOK {
		t.Fatalf("stop (provisioned) = %d, want exitOK", got)
	}
	if *stops != 1 {
		t.Errorf("StopService called %d times, want 1", *stops)
	}
}
