package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/config"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

// writePrivsepConfig writes a ~/.byn/config into the fake daemon's dir that
// turns [security] privsep on (or off, when on=false). The CLI reads this same
// file via config.Load to learn whether to route exec through exec.spawn.
func writePrivsepConfig(t *testing.T, dir string, on bool) {
	t.Helper()
	body := "[security]\nprivsep = " + map[bool]string{true: "true", false: "false"}[on] + "\n"
	if err := os.WriteFile(filepath.Join(dir, config.Filename), []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// TestRunExec_PrivsepOff_UsesLegacy: with no config (privsep absent ⇒ OFF), a
// trusted-.byn exec takes the legacy exec.fetch path, NOT exec.spawn.
func TestRunExec_PrivsepOff_UsesLegacy(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{})
	fd.onOK(ipc.OpExecSpawn, ipc.ExecSpawnResp{ExitCode: 7})

	// Missing binary → LookPath fails after the exec.fetch round-trip (legacy).
	rc := runExec([]string{"--", "byn-no-such-binary-zzz"}, cliScope{SourcePath: "/proj/.byn"})
	if rc != exitErr {
		t.Fatalf("rc = %d, want exitErr (%d)", rc, exitErr)
	}
	if calls := fd.callsFor(ipc.OpExecFetch); len(calls) != 1 {
		t.Errorf("exec.fetch calls = %d, want 1 (legacy path)", len(calls))
	}
	if calls := fd.callsFor(ipc.OpExecSpawn); len(calls) != 0 {
		t.Errorf("exec.spawn calls = %d, want 0 (privsep off)", len(calls))
	}
}

// TestRunExec_PrivsepOn_RoutesToSpawn: with [security] privsep=true and a
// trusted .byn, a direct exec routes through exec.spawn, sends the request, and
// propagates the daemon-returned child exit code (7).
func TestRunExec_PrivsepOn_RoutesToSpawn(t *testing.T) {
	fd := startFakeDaemon(t)
	writePrivsepConfig(t, fd.dir, true)
	fd.onOK(ipc.OpExecSpawn, ipc.ExecSpawnResp{ExitCode: 7})
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{}) // must NOT be used

	// "echo" resolves on PATH so the privsep branch reaches CallWithFDs.
	rc := runExec([]string{"--", "echo", "hi"}, cliScope{SourcePath: "/proj/.byn"})
	if rc != 7 {
		t.Fatalf("rc = %d, want child exit code 7", rc)
	}
	if calls := fd.callsFor(ipc.OpExecSpawn); len(calls) != 1 {
		t.Fatalf("exec.spawn calls = %d, want 1", len(calls))
	}
	if calls := fd.callsFor(ipc.OpExecFetch); len(calls) != 0 {
		t.Errorf("exec.fetch calls = %d, want 0 (privsep path bypasses fetch)", len(calls))
	}
	// The spawned request must carry the embedded ExecFetchReq + AbsTarget.
	var req ipc.ExecSpawnReq
	requireUnmarshal(t, fd.callsFor(ipc.OpExecSpawn)[0].Body, &req)
	if req.Path != "/proj/.byn" {
		t.Errorf("Path = %q, want /proj/.byn", req.Path)
	}
	if len(req.Argv) != 2 || req.Argv[0] != "echo" || req.Argv[1] != "hi" {
		t.Errorf("Argv = %v, want [echo hi]", req.Argv)
	}
	if !filepath.IsAbs(req.AbsTarget) || filepath.Base(req.AbsTarget) != "echo" {
		t.Errorf("AbsTarget = %q, want an absolute path ending in echo", req.AbsTarget)
	}
	if len(req.BaseEnv) == 0 {
		t.Errorf("BaseEnv empty, want the CLI environment forwarded")
	}
}

// TestRunExec_NoPrivsepFlag_ForcesLegacy: --no-privsep forces the legacy path
// even when [security] privsep=true.
func TestRunExec_NoPrivsepFlag_ForcesLegacy(t *testing.T) {
	fd := startFakeDaemon(t)
	writePrivsepConfig(t, fd.dir, true)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{})
	fd.onOK(ipc.OpExecSpawn, ipc.ExecSpawnResp{ExitCode: 7})

	// Missing binary → LookPath fails after the legacy exec.fetch round-trip.
	rc := runExec([]string{"--no-privsep", "--", "byn-no-such-binary-zzz"},
		cliScope{SourcePath: "/proj/.byn"})
	if rc != exitErr {
		t.Fatalf("rc = %d, want exitErr (%d)", rc, exitErr)
	}
	if calls := fd.callsFor(ipc.OpExecSpawn); len(calls) != 0 {
		t.Errorf("exec.spawn calls = %d, want 0 (--no-privsep forces legacy)", len(calls))
	}
	if calls := fd.callsFor(ipc.OpExecFetch); len(calls) != 1 {
		t.Errorf("exec.fetch calls = %d, want 1 (legacy)", len(calls))
	}
}

// TestRunExec_PrivsepNotProvisioned_HardError: privsep on, but the daemon
// reports it is not provisioned (CodeBadRequest recover "byn setup"). The CLI
// must print an actionable error and exit non-zero WITHOUT falling back.
func TestRunExec_PrivsepNotProvisioned_HardError(t *testing.T) {
	fd := startFakeDaemon(t)
	writePrivsepConfig(t, fd.dir, true)
	fd.on(ipc.OpExecSpawn, func(_ []byte) (any, *ipc.ErrMsg) {
		return nil, &ipc.ErrMsg{
			Code:    ipc.CodeBadRequest,
			Message: "privsep not provisioned (run `byn setup`)",
			Recover: "byn setup",
		}
	})
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{}) // must NOT be used as a fallback

	var rc int
	out := captureStderr(t, func() {
		rc = runExec([]string{"--", "echo", "hi"}, cliScope{SourcePath: "/proj/.byn"})
	})
	if rc != exitDaemonErr {
		t.Fatalf("rc = %d, want exitDaemonErr (%d)", rc, exitDaemonErr)
	}
	if !strings.Contains(out, "not set up") {
		t.Errorf("stderr = %q, want 'not set up' message", out)
	}
	if !strings.Contains(out, "byn setup") {
		t.Errorf("stderr = %q, want 'byn setup' hint", out)
	}
	// Must NOT have fallen back to the legacy exec.fetch path.
	if calls := fd.callsFor(ipc.OpExecFetch); len(calls) != 0 {
		t.Errorf("exec.fetch calls = %d, want 0 (no silent fallback)", len(calls))
	}
}

// TestRunExec_PrivsepOn_DaemonTooOld_FallsBack: privsep on, but the daemon does
// not implement exec.spawn (unknown_op). The CLI gracefully falls back to the
// legacy exec.fetch path. The legacy fetch is stubbed to return locked so the
// fallback short-circuits BEFORE syscall.Exec would replace the test process —
// proving both the spawn attempt AND the fallback fetch happened.
func TestRunExec_PrivsepOn_DaemonTooOld_FallsBack(t *testing.T) {
	fd := startFakeDaemon(t)
	writePrivsepConfig(t, fd.dir, true)
	// Explicit unknown_op handler for exec.spawn so the call is RECORDED (the
	// fake daemon only records ops with a registered handler) while still
	// signalling a daemon that predates exec.spawn.
	fd.onErr(ipc.OpExecSpawn, ipc.CodeUnknownOp, "unknown op")
	// The legacy fetch returns locked so the fallback exits before syscall.Exec.
	fd.onErr(ipc.OpExecFetch, ipc.CodeLocked, "vault is locked")

	var rc int
	captureStderr(t, func() {
		rc = runExec([]string{"--", "echo", "hi"}, cliScope{SourcePath: "/proj/.byn"})
	})
	if rc != exitDaemonErr {
		t.Fatalf("rc = %d, want exitDaemonErr (%d) from the legacy fallback", rc, exitDaemonErr)
	}
	if calls := fd.callsFor(ipc.OpExecSpawn); len(calls) != 1 {
		t.Errorf("exec.spawn calls = %d, want 1 (attempted before fallback)", len(calls))
	}
	if calls := fd.callsFor(ipc.OpExecFetch); len(calls) != 1 {
		t.Errorf("exec.fetch calls = %d, want 1 (legacy fallback reached)", len(calls))
	}
}

// TestRunExec_AdHocPrivsepOn_UsesLegacy: ad-hoc exec (no .byn) with privsep on
// uses the legacy in-process path (privsep confines trusted-.byn pinned exec
// only — ad-hoc has no .byn to bind the spawn to).
func TestRunExec_AdHocPrivsepOn_UsesLegacy(t *testing.T) {
	fd := startFakeDaemon(t)
	writePrivsepConfig(t, fd.dir, true)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{})
	fd.onOK(ipc.OpExecSpawn, ipc.ExecSpawnResp{ExitCode: 7})

	// No SourcePath ⇒ ad-hoc. Missing binary → LookPath fails after exec.fetch.
	rc := runExec([]string{"--", "byn-no-such-binary-zzz"}, cliScope{})
	if rc != exitErr {
		t.Fatalf("rc = %d, want exitErr (%d)", rc, exitErr)
	}
	if calls := fd.callsFor(ipc.OpExecSpawn); len(calls) != 0 {
		t.Errorf("exec.spawn calls = %d, want 0 (ad-hoc uses legacy)", len(calls))
	}
	if calls := fd.callsFor(ipc.OpExecFetch); len(calls) != 1 {
		t.Errorf("exec.fetch calls = %d, want 1 (legacy)", len(calls))
	}
}

// TestStripNoPrivsep covers the flag-stripping boundary logic.
func TestStripNoPrivsep(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		wantOut []string
		wantHit bool
	}{
		{"absent direct", []string{"--", "echo", "hi"}, []string{"--", "echo", "hi"}, false},
		{"present before sep", []string{"--no-privsep", "--", "echo"}, []string{"--", "echo"}, true},
		{"present before alias", []string{"--no-privsep", "deploy"}, []string{"deploy"}, true},
		{"after sep is child argv", []string{"--", "tool", "--no-privsep"}, []string{"--", "tool", "--no-privsep"}, false},
		{"after alias is child argv", []string{"deploy", "--no-privsep"}, []string{"deploy", "--no-privsep"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, hit := stripNoPrivsep(tc.in)
			if hit != tc.wantHit {
				t.Errorf("hit = %v, want %v", hit, tc.wantHit)
			}
			if strings.Join(got, "\x00") != strings.Join(tc.wantOut, "\x00") {
				t.Errorf("out = %v, want %v", got, tc.wantOut)
			}
		})
	}
}
