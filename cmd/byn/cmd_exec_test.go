package main

import (
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestRunExec_NoSeparator(t *testing.T) {
	if got := runExec([]string{"echo", "hi"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunExec_EmptyChildArgv(t *testing.T) {
	if got := runExec([]string{"--"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunExec_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runExec([]string{"--", "echo", "hi"}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

// TestRunExec_ExecFetchLocked verifies that a CodeLocked reply from exec.fetch
// routes through handleCallError and exits with exitDaemonErr.
func TestRunExec_ExecFetchLocked(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpExecFetch, ipc.CodeLocked, "vault is locked")
	if got := runExec([]string{"--", "echo", "hi"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}

// TestRunExec_BinaryNotInPath verifies that a missing binary fails with exitErr
// after a successful exec.fetch round-trip.
func TestRunExec_BinaryNotInPath(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{})
	if got := runExec([]string{"--", "byn-no-such-binary-zzz"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

// TestRunExec_TrustDenied verifies that a CodeTrustDenied reply renders the
// daemon's reason, prints the recovery hint, and exits non-zero.
func TestRunExec_TrustDenied(t *testing.T) {
	fd := startFakeDaemon(t)
	bynPath := "/x/.byn"
	fd.on(ipc.OpExecFetch, func(_ []byte) (any, *ipc.ErrMsg) {
		return nil, &ipc.ErrMsg{
			Code:    ipc.CodeTrustDenied,
			Message: bynPath + " has CHANGED since you trusted it",
			Recover: "byn trust " + bynPath,
		}
	})
	var trustDeniedRc int
	out := captureStderr(t, func() {
		trustDeniedRc = runExec([]string{"--", "echo"}, cliScope{SourcePath: bynPath})
	})
	if trustDeniedRc != exitDaemonErr {
		t.Errorf("trust denied exit code = %d, want exitDaemonErr (%d)", trustDeniedRc, exitDaemonErr)
	}
	if !strings.Contains(out, "has CHANGED since you trusted it") {
		t.Errorf("expected reason in stderr, got: %q", out)
	}
	if !strings.Contains(out, "byn trust "+bynPath) {
		t.Errorf("expected recovery hint in stderr, got: %q", out)
	}
}

// TestRunExec_UnknownOp verifies that when the daemon doesn't know exec.fetch
// (old daemon), the "daemon is older" message + restart hint is printed.
func TestRunExec_UnknownOp(t *testing.T) {
	// startFakeDaemon already returns unknown_op for unregistered ops.
	startFakeDaemon(t)
	var unknownOpRc int
	out := captureStderr(t, func() {
		unknownOpRc = runExec([]string{"--", "echo"}, cliScope{})
	})
	if unknownOpRc == exitOK {
		t.Errorf("expected non-zero exit, got %d", unknownOpRc)
	}
	if !strings.Contains(out, "daemon is older") {
		t.Errorf("expected 'daemon is older' in stderr, got: %q", out)
	}
	if !strings.Contains(out, "byn restart") {
		t.Errorf("expected 'byn restart' hint in stderr, got: %q", out)
	}
}

// TestRunExec_WireBody asserts the exec.fetch request body contains the
// expected Path, Scope, and Command fields.
func TestRunExec_WireBody(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{})

	bynPath := "/proj/.byn"
	scope := cliScope{
		SourcePath: bynPath,
		Vault:      "acme",
		Project:    "web",
		Env:        "dev",
	}
	// Missing binary causes LookPath failure after IPC, which is fine —
	// we only care about what was sent on the wire.
	_ = runExec([]string{"--", "byn-no-such-binary-zzz", "--flag"}, scope)

	calls := fd.callsFor(ipc.OpExecFetch)
	if len(calls) != 1 {
		t.Fatalf("expected 1 exec.fetch call, got %d", len(calls))
	}
	var req ipc.ExecFetchReq
	requireUnmarshal(t, calls[0].Body, &req)
	if req.Path != bynPath {
		t.Errorf("Path = %q, want %q", req.Path, bynPath)
	}
	if req.Scope.Vault != "acme" || req.Scope.Project != "web" || req.Scope.Env != "dev" {
		t.Errorf("Scope = %+v, want acme/web/dev", req.Scope)
	}
	wantCmd := "byn-no-such-binary-zzz --flag"
	if req.Command != wantCmd {
		t.Errorf("Command = %q, want %q", req.Command, wantCmd)
	}
}

// TestRunExec_HappyPath_SingleOp verifies that a successful exec drives
// exactly one exec.fetch op — no trust.verify, list, or get calls.
// The binary intentionally doesn't exist so LookPath fails after the
// IPC round-trip; the test asserts: (a) exec.fetch called exactly once,
// (b) the other three ops zero times, (c) return code is exitErr.
func TestRunExec_HappyPath_SingleOp(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{
		Values: []ipc.ExecFetchValue{{Name: "DB_URL", Value: []byte("postgres://localhost/test")}},
	})
	// Register handlers for the ops that must NOT be called so that
	// callsFor can record them if they are accidentally invoked —
	// without a handler, fakeDaemon returns unknown_op and skips recording.
	fd.onOK(ipc.OpTrustVerify, ipc.TrustVerifyResp{})
	fd.onOK(ipc.OpList, ipc.ListResp{})
	fd.onOK(ipc.OpGet, ipc.GetResp{})

	// Use a missing binary to trigger LookPath failure after IPC succeeds,
	// since syscall.Exec would replace the test process if it succeeded.
	rc := runExec([]string{"--", "byn-no-such-binary-zzz"}, cliScope{})
	if rc != exitErr {
		t.Errorf("expected exitErr after LookPath failure, got %d", rc)
	}

	// Only exec.fetch should have been called.
	if calls := fd.callsFor(ipc.OpExecFetch); len(calls) != 1 {
		t.Errorf("expected 1 exec.fetch call, got %d", len(calls))
	}
	if calls := fd.callsFor(ipc.OpTrustVerify); len(calls) != 0 {
		t.Errorf("expected 0 trust.verify calls, got %d", len(calls))
	}
	if calls := fd.callsFor(ipc.OpList); len(calls) != 0 {
		t.Errorf("expected 0 list calls, got %d", len(calls))
	}
	if calls := fd.callsFor(ipc.OpGet); len(calls) != 0 {
		t.Errorf("expected 0 get calls, got %d", len(calls))
	}
}
