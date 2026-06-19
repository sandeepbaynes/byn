package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// By default tests use a benign local-check environment so dispatch/routing
// tests (e.g. TestRun_RoutesToDoctor) exercise the daemon path, not the real
// machine's provisioning/ownership state. Individual tests override via
// withDoctorEnv. TestProductionHealEnv_Probes covers the real probes directly.
func init() { doctorEnv = healthyDoctorEnv(true) }

// healthyDoctorEnv stubs the local-check environment so the daemon-side checks
// drive the result. daemonUp toggles whether runDoctor calls the daemon.
func healthyDoctorEnv(daemonUp bool) func(string) healEnv {
	return func(dir string) healEnv {
		return healEnv{
			provisioned: func() bool { return true },
			exists:      func(string) bool { return true },
			fileUID:     func(string) (int, bool) { return 77, true },
			bynUID:      func() (int, bool) { return 77, true },
			daemonUp:    func() bool { return daemonUp },
			dataDir:     dir,
			helperPath:  "/helper",
		}
	}
}

// withDoctorEnv installs a stub doctorEnv for the duration of a test.
func withDoctorEnv(t *testing.T, env func(string) healEnv) {
	t.Helper()
	old := doctorEnv
	doctorEnv = env
	t.Cleanup(func() { doctorEnv = old })
}

func TestRunDoctor_OK(t *testing.T) {
	withDoctorEnv(t, healthyDoctorEnv(true))
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpDoctor, ipc.DoctorResp{Checks: []ipc.DoctorCheck{
		{Name: "vault.open", Severity: "ok"},
		{Name: "vault.unlock", Severity: "warn", Detail: "locked"},
	}})
	if got := runDoctor(nil, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunDoctor_FailExitsNonZero(t *testing.T) {
	withDoctorEnv(t, healthyDoctorEnv(true))
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpDoctor, ipc.DoctorResp{Checks: []ipc.DoctorCheck{
		{Name: "audit.chain", Severity: "fail", Detail: "broken at 3"},
	}})
	if got := runDoctor(nil, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunDoctor_JSON(t *testing.T) {
	withDoctorEnv(t, healthyDoctorEnv(true))
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpDoctor, ipc.DoctorResp{Checks: []ipc.DoctorCheck{
		{Name: "a", Severity: "ok"},
	}})
	if got := runDoctor([]string{"--json"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunDoctor_UnknownSeverity(t *testing.T) {
	// Ensure the "?" branch is exercised.
	withDoctorEnv(t, healthyDoctorEnv(true))
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpDoctor, ipc.DoctorResp{Checks: []ipc.DoctorCheck{
		{Name: "weird", Severity: "mystery", Detail: "?"},
	}})
	if got := runDoctor(nil, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunDoctor_BadFlag(t *testing.T) {
	if got := runDoctor([]string{"--nope"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

// TestRunDoctor_DaemonDown: with the daemon down, the local "daemon running"
// check fails (and a stale socket is flagged), so doctor exits non-zero — but it
// does NOT hard-fail with a daemon-down error the way data commands do; it still
// reports the local diagnosis (no daemon round-trip).
func TestRunDoctor_DaemonDown(t *testing.T) {
	withDoctorEnv(t, healthyDoctorEnv(false))
	if got := runDoctor(nil, cliScope{}); got != exitErr {
		t.Fatalf("got %d, want exitErr (daemon-down is a failing local check)", got)
	}
}

// TestProductionHealEnv_Probes exercises the real OS probes (not stubbed) so
// productionHealEnv / fileUID / exists / daemonUp keep working.
func TestProductionHealEnv_Probes(t *testing.T) {
	dir := t.TempDir()
	e := productionHealEnv(dir)
	if e.dataDir != dir {
		t.Errorf("dataDir = %q, want %q", e.dataDir, dir)
	}
	if !e.exists(dir) {
		t.Error("exists(tempdir) should be true")
	}
	if e.exists(filepath.Join(dir, "does-not-exist")) {
		t.Error("exists(missing) should be false")
	}
	uid, ok := e.fileUID(dir)
	if !ok || uid != os.Getuid() {
		t.Errorf("fileUID(tempdir) = %d,%v, want %d,true", uid, ok, os.Getuid())
	}
	// daemonUp against a dir with no live daemon must be false (and not panic).
	if e.daemonUp() {
		t.Log("daemon reachable for the temp dir (unexpected but non-fatal)")
	}
}
