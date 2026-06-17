package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// privsepOnStatus registers an OpStatus handler reporting privsep engaged, so
// the CLI's authoritative status probe sets privsepOn=true and routes a
// trusted-.byn direct exec through the terminal-anchored authorize path.
func privsepOnStatus(fd *fakeDaemon) {
	fd.onOK(ipc.OpStatus, ipc.StatusResp{Privsep: true})
}

// stubExecHelper replaces execHelperRunner (which would spawn the real setuid
// helper) with a recorder returning rc. Returns a pointer to the token the CLI
// handed the helper, so tests can assert the one-time token was forwarded.
func stubExecHelper(t *testing.T, rc int) *[]byte {
	t.Helper()
	var got []byte
	old := execHelperRunner
	execHelperRunner = func(token []byte) int {
		got = append([]byte{}, token...)
		return rc
	}
	t.Cleanup(func() { execHelperRunner = old })
	return &got
}

// TestRunExec_PrivsepOff_UsesLegacy: status reports privsep OFF, so a
// trusted-.byn exec takes the legacy exec.fetch path, never exec.authorize.
func TestRunExec_PrivsepOff_UsesLegacy(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{Privsep: false})
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{})
	fd.onOK(ipc.OpExecAuthorize, ipc.ExecAuthorizeResp{Token: []byte("x")})

	// Missing binary → LookPath fails after the exec.fetch round-trip (legacy).
	rc := runExec([]string{"--", "byn-no-such-binary-zzz"}, cliScope{SourcePath: "/proj/.byn"})
	if rc != exitErr {
		t.Fatalf("rc = %d, want exitErr (%d)", rc, exitErr)
	}
	if calls := fd.callsFor(ipc.OpExecFetch); len(calls) != 1 {
		t.Errorf("exec.fetch calls = %d, want 1 (legacy path)", len(calls))
	}
	if calls := fd.callsFor(ipc.OpExecAuthorize); len(calls) != 0 {
		t.Errorf("exec.authorize calls = %d, want 0 (privsep off)", len(calls))
	}
}

// TestRunExec_PrivsepOn_RoutesToAuthorize: with privsep engaged and a trusted
// .byn, a direct exec routes through exec.authorize, hands the minted token to
// the helper, and propagates the helper's exit code (7). The request carries the
// embedded ExecFetchReq + the resolved AbsTarget + BaseEnv + Cwd.
func TestRunExec_PrivsepOn_RoutesToAuthorize(t *testing.T) {
	fd := startFakeDaemon(t)
	privsepOnStatus(fd)
	fd.onOK(ipc.OpExecAuthorize, ipc.ExecAuthorizeResp{Token: []byte("tok-123")})
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{}) // must NOT be used
	gotTok := stubExecHelper(t, 7)

	// "echo" resolves on PATH so the privsep branch reaches exec.authorize.
	rc := runExec([]string{"--", "echo", "hi"}, cliScope{SourcePath: "/proj/.byn"})
	if rc != 7 {
		t.Fatalf("rc = %d, want helper exit code 7", rc)
	}
	if calls := fd.callsFor(ipc.OpExecAuthorize); len(calls) != 1 {
		t.Fatalf("exec.authorize calls = %d, want 1", len(calls))
	}
	if calls := fd.callsFor(ipc.OpExecFetch); len(calls) != 0 {
		t.Errorf("exec.fetch calls = %d, want 0 (authorize path bypasses fetch)", len(calls))
	}
	if string(*gotTok) != "tok-123" {
		t.Errorf("helper token = %q, want the minted token tok-123", string(*gotTok))
	}
	var req ipc.ExecAuthorizeReq
	requireUnmarshal(t, fd.callsFor(ipc.OpExecAuthorize)[0].Body, &req)
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
	if req.Cwd == "" {
		t.Errorf("Cwd empty, want the CLI working directory forwarded")
	}
}

// TestRunExec_NoPrivsepFlag_ForcesLegacy: --no-privsep forces the legacy path
// even when status reports privsep on (the flag short-circuits the status probe).
func TestRunExec_NoPrivsepFlag_ForcesLegacy(t *testing.T) {
	fd := startFakeDaemon(t)
	privsepOnStatus(fd)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{})
	fd.onOK(ipc.OpExecAuthorize, ipc.ExecAuthorizeResp{Token: []byte("x")})

	rc := runExec([]string{"--no-privsep", "--", "byn-no-such-binary-zzz"},
		cliScope{SourcePath: "/proj/.byn"})
	if rc != exitErr {
		t.Fatalf("rc = %d, want exitErr (%d)", rc, exitErr)
	}
	if calls := fd.callsFor(ipc.OpExecAuthorize); len(calls) != 0 {
		t.Errorf("exec.authorize calls = %d, want 0 (--no-privsep forces legacy)", len(calls))
	}
	if calls := fd.callsFor(ipc.OpExecFetch); len(calls) != 1 {
		t.Errorf("exec.fetch calls = %d, want 1 (legacy)", len(calls))
	}
}

// TestRunExec_PrivsepNotProvisioned_HardError: privsep on, but the daemon reports
// it is not provisioned. The CLI prints an actionable error, exits non-zero,
// never falls back to legacy, and never invokes the helper.
func TestRunExec_PrivsepNotProvisioned_HardError(t *testing.T) {
	fd := startFakeDaemon(t)
	privsepOnStatus(fd)
	fd.on(ipc.OpExecAuthorize, func(_ []byte) (any, *ipc.ErrMsg) {
		return nil, &ipc.ErrMsg{
			Code:    ipc.CodeBadRequest,
			Message: "privsep not provisioned (run `byn setup`)",
			Recover: "byn setup",
		}
	})
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{}) // must NOT be used as a fallback
	gotTok := stubExecHelper(t, 0)

	var rc int
	out := captureStderr(t, func() {
		rc = runExec([]string{"--", "echo", "hi"}, cliScope{SourcePath: "/proj/.byn"})
	})
	if rc != exitDaemonErr {
		t.Fatalf("rc = %d, want exitDaemonErr (%d)", rc, exitDaemonErr)
	}
	if !strings.Contains(out, "not set up") || !strings.Contains(out, "byn setup") {
		t.Errorf("stderr = %q, want 'not set up' + 'byn setup' hint", out)
	}
	if calls := fd.callsFor(ipc.OpExecFetch); len(calls) != 0 {
		t.Errorf("exec.fetch calls = %d, want 0 (no silent fallback)", len(calls))
	}
	if len(*gotTok) != 0 {
		t.Errorf("helper was invoked with %q, want not invoked on not-provisioned", string(*gotTok))
	}
}

// TestRunExec_PrivsepOn_DaemonTooOld_FallsBack: privsep on, but the daemon does
// not implement exec.authorize (unknown_op). The CLI falls back to the legacy
// exec.fetch path. Legacy fetch returns locked so the fallback short-circuits
// before syscall.Exec would replace the test process.
func TestRunExec_PrivsepOn_DaemonTooOld_FallsBack(t *testing.T) {
	fd := startFakeDaemon(t)
	privsepOnStatus(fd)
	fd.onErr(ipc.OpExecAuthorize, ipc.CodeUnknownOp, "unknown op")
	fd.onErr(ipc.OpExecFetch, ipc.CodeLocked, "vault is locked")

	var rc int
	captureStderr(t, func() {
		rc = runExec([]string{"--", "echo", "hi"}, cliScope{SourcePath: "/proj/.byn"})
	})
	if rc != exitDaemonErr {
		t.Fatalf("rc = %d, want exitDaemonErr (%d) from the legacy fallback", rc, exitDaemonErr)
	}
	if calls := fd.callsFor(ipc.OpExecAuthorize); len(calls) != 1 {
		t.Errorf("exec.authorize calls = %d, want 1 (attempted before fallback)", len(calls))
	}
	if calls := fd.callsFor(ipc.OpExecFetch); len(calls) != 1 {
		t.Errorf("exec.fetch calls = %d, want 1 (legacy fallback reached)", len(calls))
	}
}

// TestRunExec_PrivsepOn_AuthRequiredNonTTY: an auth_required reply from
// exec.authorize on a non-TTY (no password prompt possible) is a clean
// daemon-error exit; the helper is never invoked.
func TestRunExec_PrivsepOn_AuthRequiredNonTTY(t *testing.T) {
	fd := startFakeDaemon(t)
	privsepOnStatus(fd)
	fd.onErr(ipc.OpExecAuthorize, ipc.CodeAuthRequired, "command not pinned in /proj/.byn [exec] actions")
	gotTok := stubExecHelper(t, 0)
	// Pipe stdin so stdinIsTTY() is false — no password prompt, no retry.
	withStdin(t, "")

	var rc int
	captureStderr(t, func() {
		rc = runExec([]string{"--", "echo", "hi"}, cliScope{SourcePath: "/proj/.byn"})
	})
	if rc != exitDaemonErr {
		t.Fatalf("rc = %d, want exitDaemonErr (%d)", rc, exitDaemonErr)
	}
	if len(*gotTok) != 0 {
		t.Errorf("helper invoked despite auth_required; want not invoked")
	}
}

// TestRunExec_AdHocPrivsepOn_UsesLegacy: ad-hoc exec (no .byn) with privsep on
// uses the legacy in-process path (the terminal-anchored path confines
// trusted-.byn pinned exec only — ad-hoc has no .byn to bind the spawn to).
func TestRunExec_AdHocPrivsepOn_UsesLegacy(t *testing.T) {
	fd := startFakeDaemon(t)
	privsepOnStatus(fd)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{})
	fd.onOK(ipc.OpExecAuthorize, ipc.ExecAuthorizeResp{Token: []byte("x")})

	// No SourcePath ⇒ ad-hoc. Missing binary → LookPath fails after exec.fetch.
	rc := runExec([]string{"--", "byn-no-such-binary-zzz"}, cliScope{})
	if rc != exitErr {
		t.Fatalf("rc = %d, want exitErr (%d)", rc, exitErr)
	}
	if calls := fd.callsFor(ipc.OpExecAuthorize); len(calls) != 0 {
		t.Errorf("exec.authorize calls = %d, want 0 (ad-hoc uses legacy)", len(calls))
	}
	if calls := fd.callsFor(ipc.OpExecFetch); len(calls) != 1 {
		t.Errorf("exec.fetch calls = %d, want 1 (legacy)", len(calls))
	}
}

// TestRunExec_NoPrivsep_SendsForceAuth: --no-privsep routes to the legacy fetch
// path AND sets ForceAuth=true so the daemon demands the master password every
// run (the child runs as the owner with the injected env exposed).
func TestRunExec_NoPrivsep_SendsForceAuth(t *testing.T) {
	fd := startFakeDaemon(t)
	privsepOnStatus(fd) // privsep engaged — but --no-privsep forces legacy + ForceAuth
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{})

	// Non-existent binary → LookPath fails after the fetch round-trip (no exec).
	rc := runExec([]string{"--no-privsep", "--", "byn-no-such-binary-zzz"},
		cliScope{SourcePath: "/proj/.byn"})
	if rc != exitErr {
		t.Fatalf("rc = %d, want exitErr (%d)", rc, exitErr)
	}
	calls := fd.callsFor(ipc.OpExecFetch)
	if len(calls) != 1 {
		t.Fatalf("exec.fetch calls = %d, want 1 (legacy path)", len(calls))
	}
	var req ipc.ExecFetchReq
	requireUnmarshal(t, calls[0].Body, &req)
	if !req.ForceAuth {
		t.Error("--no-privsep must set ForceAuth=true on the exec.fetch request")
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
