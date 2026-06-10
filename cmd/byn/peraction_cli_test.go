package main

import (
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// authRequiredThenOK is the sibling of lockedThenOK: the first call replies
// CodeAuthRequired, every later call replies with okBody.
func authRequiredThenOK(okBody any) func([]byte) (any, *ipc.ErrMsg) {
	first := true
	return func([]byte) (any, *ipc.ErrMsg) {
		if first {
			first = false
			return nil, &ipc.ErrMsg{Code: ipc.CodeAuthRequired, Message: "per_action_auth: password required"}
		}
		return okBody, nil
	}
}

// authRequiredThenLocked mimics: flag on + vault locked. First call →
// CodeAuthRequired, second call (with password) → CodeLocked.
func authRequiredThenLocked() func([]byte) (any, *ipc.ErrMsg) {
	first := true
	return func([]byte) (any, *ipc.ErrMsg) {
		if first {
			first = false
			return nil, &ipc.ErrMsg{Code: ipc.CodeAuthRequired, Message: "per_action_auth: password required"}
		}
		return nil, &ipc.ErrMsg{Code: ipc.CodeLocked, Message: "vault is locked", Recover: "byn unlock"}
	}
}

// authRequiredThenWrongPassword: first call → auth_required, retry → wrong_password.
func authRequiredThenWrongPassword() func([]byte) (any, *ipc.ErrMsg) {
	first := true
	return func([]byte) (any, *ipc.ErrMsg) {
		if first {
			first = false
			return nil, &ipc.ErrMsg{Code: ipc.CodeAuthRequired, Message: "per_action_auth: password required"}
		}
		return nil, &ipc.ErrMsg{Code: ipc.CodeWrongPassword, Message: "wrong password"}
	}
}

// ---------------------------------------------------------------------------
// byn get
// ---------------------------------------------------------------------------

func TestGetPromptsOnAuthRequired(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpGet, authRequiredThenOK(ipc.GetResp{Value: []byte("s3cr3t")}))
	// Supply password via stdin (simulates the interactive prompt path in tests).
	withStdin(t, "hunter2\n")
	var rc int
	out := captureStdout(t, func() {
		rc = runGet([]string{"--password-stdin", "MY_KEY"}, cliScope{})
	})
	if rc != exitOK {
		t.Fatalf("rc = %d, want exitOK", rc)
	}
	if !strings.Contains(out, "s3cr3t") {
		t.Errorf("stdout = %q, want s3cr3t in output", out)
	}
	// Verify two calls were made, and the retry carried the password.
	calls := fd.callsFor(ipc.OpGet)
	if len(calls) != 2 {
		t.Fatalf("got %d get calls, want 2 (auth_required then retry)", len(calls))
	}
	var firstReq ipc.GetReq
	requireUnmarshal(t, calls[0].Body, &firstReq)
	if len(firstReq.Password) != 0 {
		t.Errorf("first call carried a password: %q", firstReq.Password)
	}
	var retryReq ipc.GetReq
	requireUnmarshal(t, calls[1].Body, &retryReq)
	if string(retryReq.Password) != "hunter2" {
		t.Errorf("retry password = %q, want hunter2", retryReq.Password)
	}
}

func TestGetAuthRequiredPasswordStdin(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpGet, authRequiredThenOK(ipc.GetResp{Value: []byte("myval")}))
	withStdin(t, "mypassword\n")
	var rc int
	out := captureStdout(t, func() {
		rc = runGet([]string{"--password-stdin", "MYKEY"}, cliScope{})
	})
	if rc != exitOK {
		t.Fatalf("rc = %d, want exitOK", rc)
	}
	if !strings.Contains(out, "myval") {
		t.Errorf("stdout = %q, want myval", out)
	}
	calls := fd.callsFor(ipc.OpGet)
	if len(calls) != 2 {
		t.Fatalf("got %d calls, want 2", len(calls))
	}
	var req ipc.GetReq
	requireUnmarshal(t, calls[1].Body, &req)
	if string(req.Password) != "mypassword" {
		t.Errorf("retry password = %q, want mypassword", req.Password)
	}
}

// TestGetAuthRequiredJSONModeHardFails: when --json is set, get must never
// prompt; it must fail with an actionable message naming per_action_auth and
// --password-stdin, and return non-zero.
func TestGetAuthRequiredJSONModeHardFails(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpGet, authRequiredThenOK(ipc.GetResp{Value: []byte("val")}))
	var rc int
	errOut := captureStderr(t, func() {
		rc = runGet([]string{"--json", "MY_KEY"}, cliScope{})
	})
	if rc == exitOK {
		t.Fatalf("json mode should fail on auth_required, got exitOK")
	}
	if !strings.Contains(errOut, "per_action_auth") {
		t.Errorf("stderr = %q, want per_action_auth mentioned", errOut)
	}
	if !strings.Contains(errOut, "--password-stdin") {
		t.Errorf("stderr = %q, want --password-stdin mentioned", errOut)
	}
	// Must not have made a retry call.
	calls := fd.callsFor(ipc.OpGet)
	if len(calls) != 1 {
		t.Fatalf("json mode should NOT retry, got %d calls", len(calls))
	}
}

// TestGetAuthRequiredThenLockedRendersUnlockHint: per_action_auth on + vault
// locked. First call → auth_required; retry (with pw) → locked. The locked
// error should be rendered with the unlock hint (not an infinite loop).
func TestGetAuthRequiredThenLockedRendersUnlockHint(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpGet, authRequiredThenLocked())
	withStdin(t, "hunter2\n")
	var rc int
	errOut := captureStderr(t, func() {
		rc = runGet([]string{"--password-stdin", "KEY"}, cliScope{})
	})
	if rc == exitOK {
		t.Fatalf("should fail when vault is locked after auth retry, got exitOK")
	}
	// handleCallError should have rendered the locked message with byn unlock hint.
	if !strings.Contains(errOut, "locked") && !strings.Contains(errOut, "unlock") {
		t.Errorf("stderr = %q, want locked/unlock hint in output", errOut)
	}
	// Exactly two calls: first (no pw) → auth_required, second (with pw) → locked.
	calls := fd.callsFor(ipc.OpGet)
	if len(calls) != 2 {
		t.Fatalf("got %d get calls, want exactly 2", len(calls))
	}
}

// TestAuthRequiredWrongPasswordRendered: retry → wrong_password must be
// rendered actionably without infinite looping.
func TestAuthRequiredWrongPasswordRendered(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpGet, authRequiredThenWrongPassword())
	withStdin(t, "wrongpw\n")
	var rc int
	errOut := captureStderr(t, func() {
		rc = runGet([]string{"--password-stdin", "KEY"}, cliScope{})
	})
	if rc == exitOK {
		t.Fatalf("wrong password should fail, got exitOK")
	}
	if !strings.Contains(errOut, "wrong") && !strings.Contains(errOut, "password") {
		t.Errorf("stderr = %q, want wrong password mentioned", errOut)
	}
	// Exactly two calls (no infinite loop).
	calls := fd.callsFor(ipc.OpGet)
	if len(calls) != 2 {
		t.Fatalf("got %d get calls, want exactly 2 (no infinite retry)", len(calls))
	}
}

// ---------------------------------------------------------------------------
// byn delete
// ---------------------------------------------------------------------------

func TestDeleteAuthRequiredRetries(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpDelete, authRequiredThenOK(ipc.DeleteResp{}))
	withStdin(t, "hunter2\n")
	if got := runDelete([]string{"--password-stdin", "API_KEY"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
	calls := fd.callsFor(ipc.OpDelete)
	if len(calls) != 2 {
		t.Fatalf("got %d delete calls, want 2", len(calls))
	}
	var req ipc.DeleteReq
	requireUnmarshal(t, calls[1].Body, &req)
	if string(req.Password) != "hunter2" {
		t.Errorf("retry password = %q, want hunter2", req.Password)
	}
}

// ---------------------------------------------------------------------------
// byn put (overwrite)
// ---------------------------------------------------------------------------

// TestPutOverwriteAuthRequiredRetries verifies the first-line-is-password
// contract: when --password-stdin is set, the first line of stdin is the
// master password and the remainder is the secret value. The retry carries
// the pre-read password, not an empty buffer.
func TestPutOverwriteAuthRequiredRetries(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpPut, authRequiredThenOK(ipc.PutResp{}))
	// First line = password, remainder = secret value (no trailing newline on value).
	withStdin(t, "pw\nthe-value")
	rc := runPut([]string{"--password-stdin", "MYKEY"}, cliScope{})
	if rc != exitOK {
		t.Fatalf("put with auth_required retry got rc=%d, want exitOK", rc)
	}
	calls := fd.callsFor(ipc.OpPut)
	if len(calls) != 2 {
		t.Fatalf("got %d put calls, want 2 (auth_required then retry)", len(calls))
	}
	// First call must carry no password.
	var firstReq ipc.PutReq
	requireUnmarshal(t, calls[0].Body, &firstReq)
	if len(firstReq.Password) != 0 {
		t.Errorf("first put call carried a password: %q", firstReq.Password)
	}
	// Retry must carry the pre-read password "pw".
	var retryReq ipc.PutReq
	requireUnmarshal(t, calls[1].Body, &retryReq)
	if string(retryReq.Password) != "pw" {
		t.Errorf("retry password = %q, want pw", retryReq.Password)
	}
	// The stored value must be the remainder after the first line.
	if string(retryReq.Value) != "the-value" {
		t.Errorf("stored value = %q, want the-value", retryReq.Value)
	}
}

// TestPutPasswordStdinFlagOffStillWorks: flag off (no auth_required), piped
// "pw\nvalue" with --password-stdin → put succeeds with value "value" (first
// line consumed per contract).
func TestPutPasswordStdinFlagOffStillWorks(t *testing.T) {
	fd := startFakeDaemon(t)
	// No auth gate — daemon accepts first call.
	fd.onOK(ipc.OpPut, ipc.PutResp{})
	// Even though the daemon never asks for auth, first line is consumed.
	withStdin(t, "pw\nvalue")
	rc := runPut([]string{"--password-stdin", "MYKEY"}, cliScope{})
	if rc != exitOK {
		t.Fatalf("put without auth_required got rc=%d, want exitOK", rc)
	}
	calls := fd.callsFor(ipc.OpPut)
	if len(calls) != 1 {
		t.Fatalf("got %d put calls, want 1 (no retry needed)", len(calls))
	}
	var req ipc.PutReq
	requireUnmarshal(t, calls[0].Body, &req)
	// The stored value must be the remainder after the consumed first line.
	if string(req.Value) != "value" {
		t.Errorf("stored value = %q, want value", req.Value)
	}
}

// TestGetJSONWithPasswordStdinWorks: --json --password-stdin together must work
// (reading piped stdin is not prompting). auth_required then success → value
// printed, no prompt error, exactly 2 calls.
func TestGetJSONWithPasswordStdinWorks(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpGet, authRequiredThenOK(ipc.GetResp{Value: []byte("secret")}))
	withStdin(t, "mypw\n")
	var rc int
	out := captureStdout(t, func() {
		rc = runGet([]string{"--json", "--password-stdin", "MY_KEY"}, cliScope{})
	})
	if rc != exitOK {
		t.Fatalf("--json --password-stdin got rc=%d, want exitOK", rc)
	}
	if out == "" {
		t.Error("expected JSON output, got empty stdout")
	}
	calls := fd.callsFor(ipc.OpGet)
	if len(calls) != 2 {
		t.Fatalf("got %d get calls, want 2 (auth_required then retry)", len(calls))
	}
	var retryReq ipc.GetReq
	requireUnmarshal(t, calls[1].Body, &retryReq)
	if string(retryReq.Password) != "mypw" {
		t.Errorf("retry password = %q, want mypw", retryReq.Password)
	}
}

// TestPutWithoutFlagUnchanged: no --password-stdin → entire stdin is the value
// (existing behavior pinned).
func TestPutWithoutFlagUnchanged(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpPut, ipc.PutResp{})
	// No --password-stdin: whole stdin is the value.
	withStdin(t, "pw\nvalue")
	rc := runPut([]string{"MYKEY"}, cliScope{})
	if rc != exitOK {
		t.Fatalf("put without flag got rc=%d, want exitOK", rc)
	}
	calls := fd.callsFor(ipc.OpPut)
	if len(calls) != 1 {
		t.Fatalf("got %d put calls, want 1", len(calls))
	}
	var req ipc.PutReq
	requireUnmarshal(t, calls[0].Body, &req)
	// Whole stdin (minus trailing newline stripping for single-line) is the value.
	// "pw\nvalue" — readSecretValue strips a single trailing newline only.
	// Here there's no trailing newline, so the full string is kept.
	if string(req.Value) != "pw\nvalue" {
		t.Errorf("stored value = %q, want pw\\nvalue", req.Value)
	}
}

// ---------------------------------------------------------------------------
// byn rename
// ---------------------------------------------------------------------------

func TestRenameAuthRequiredRetries(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpRename, authRequiredThenOK(ipc.RenameResp{}))
	withStdin(t, "s3cret\n")
	if got := runRename([]string{"--password-stdin", "old", "new"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
	calls := fd.callsFor(ipc.OpRename)
	if len(calls) != 2 {
		t.Fatalf("got %d rename calls, want 2", len(calls))
	}
	var req ipc.RenameReq
	requireUnmarshal(t, calls[1].Body, &req)
	if string(req.Password) != "s3cret" {
		t.Errorf("retry password = %q, want s3cret", req.Password)
	}
}

// ---------------------------------------------------------------------------
// byn get — locked-vault fast-fail (fix 2)
// ---------------------------------------------------------------------------

// TestGetLockedNoRetryFailsFast: when the vault is locked, get must fail fast
// (exactly 1 IPC call) with the locked rendering and "byn unlock" hint. It
// must NOT prompt or retry regardless of whether --password-stdin is set,
// because a correct password still yields CodeLocked (the vault key must be
// in memory to decrypt).
func TestGetLockedNoRetryFailsFast(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpGet, ipc.CodeLocked, "vault is locked")
	var rc int
	errOut := captureStderr(t, func() {
		rc = runGet([]string{"MY_KEY"}, cliScope{})
	})
	if rc == exitOK {
		t.Fatalf("locked vault should fail, got exitOK")
	}
	if !strings.Contains(errOut, "locked") {
		t.Errorf("stderr = %q, want 'locked' in output", errOut)
	}
	// Exactly one IPC call — no retry loop.
	calls := fd.callsFor(ipc.OpGet)
	if len(calls) != 1 {
		t.Fatalf("locked get made %d IPC calls, want exactly 1 (no retry)", len(calls))
	}
}

// TestGetJSONLockedMessage: --json mode with a locked vault must print
// "byn unlock" (not "--password-stdin") and make exactly 1 IPC call.
func TestGetJSONLockedMessage(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpGet, ipc.CodeLocked, "vault is locked")
	var rc int
	errOut := captureStderr(t, func() {
		rc = runGet([]string{"--json", "MY_KEY"}, cliScope{})
	})
	if rc == exitOK {
		t.Fatalf("locked vault --json should fail, got exitOK")
	}
	// The guard must name "byn unlock", not "--password-stdin".
	if !strings.Contains(errOut, "unlock") {
		t.Errorf("stderr = %q, want 'unlock' mentioned", errOut)
	}
	if strings.Contains(errOut, "--password-stdin") {
		t.Errorf("stderr = %q, must NOT mention --password-stdin for locked vault", errOut)
	}
	// Exactly one IPC call.
	calls := fd.callsFor(ipc.OpGet)
	if len(calls) != 1 {
		t.Fatalf("locked --json get made %d IPC calls, want exactly 1", len(calls))
	}
}

// TestPutPasswordStdinOnTTYFailsFast cannot be tested as a real unit test
// because the withStdin helper creates an os.Pipe(), which is never a TTY —
// stdinIsTTY() would always return false for it. A real TTY can only be
// obtained by allocating a pty (e.g. golang.org/x/term.Open), which is not
// worth adding as a test dependency here. The behaviour is covered by manual
// testing: running `byn put key --password-stdin` at an interactive terminal
// prints "stdin is a terminal" and exits 1 without reading any input.

// ---------------------------------------------------------------------------
// byn env clear
// ---------------------------------------------------------------------------

func TestEnvClearAuthRequiredRetries(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpEnvClear, authRequiredThenOK(ipc.EnvClearResp{Deleted: 3}))
	withStdin(t, "s3cret\n")
	if got := runEnvClear([]string{"--yes", "--password-stdin", "default"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
	calls := fd.callsFor(ipc.OpEnvClear)
	if len(calls) != 2 {
		t.Fatalf("got %d env clear calls, want 2", len(calls))
	}
	var req ipc.EnvClearReq
	requireUnmarshal(t, calls[1].Body, &req)
	if string(req.Password) != "s3cret" {
		t.Errorf("retry password = %q, want s3cret", req.Password)
	}
}

// ---------------------------------------------------------------------------
// byn exec — ad-hoc auth_required gate
// ---------------------------------------------------------------------------

// TestExecAdHocAuthRequired_NonTTY_FailsFast: ad-hoc exec (no .byn) gets
// auth_required from the daemon. When stdin is not a TTY (redirected to a
// pipe via withStdin), the CLI prints an actionable error and fails with
// exitDaemonErr — no retry, no infinite loop.
func TestExecAdHocAuthRequired_NonTTY_FailsFast(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpExecFetch, authRequiredThenOK(ipc.ExecFetchResp{}))
	// Redirect stdin to a pipe so stdinIsTTY() returns false, forcing the
	// non-interactive fast-fail path regardless of test environment.
	withStdin(t, "")

	var rc int
	errOut := captureStderr(t, func() {
		rc = runExec([]string{"--", "byn-no-such-binary-zzz"}, cliScope{})
	})
	if rc != exitDaemonErr {
		t.Fatalf("non-TTY auth_required exec = rc %d, want exitDaemonErr (%d)", rc, exitDaemonErr)
	}
	// Error message should mention per_action_auth or ad-hoc exec being gated.
	if !strings.Contains(errOut, "per_action_auth") && !strings.Contains(errOut, "requires authorization") {
		t.Errorf("stderr = %q, want per_action_auth / requires authorization mentioned", errOut)
	}
	// Hint must mention .byn as the credential-free alternative.
	if !strings.Contains(errOut, ".byn") {
		t.Errorf("stderr = %q, want .byn mentioned as alternative", errOut)
	}
	// Exactly one IPC call — non-TTY must NOT retry.
	calls := fd.callsFor(ipc.OpExecFetch)
	if len(calls) != 1 {
		t.Fatalf("non-TTY auth_required made %d exec.fetch calls, want exactly 1 (no retry)", len(calls))
	}
}

// TestExecAdHocAuthRequired_WrongPasswordAfterTTYPrompt cannot be exercised
// as a pure unit test because the TTY-prompt path requires an actual
// terminal (stdinIsTTY() returns false for a test pipe). The non-TTY fast-
// fail path is covered by TestExecAdHocAuthRequired_NonTTY_FailsFast.
// Integration of the TTY retry path is verified manually and by the daemon
// tests (TestExecFetchAdHocFlagOnWithPasswordSucceeds).

// TestExecTrustedBynNotGated: trusted .byn exec makes exactly one call with
// NO password even when auth_required would fire for ad-hoc. The .byn path
// is supplied so the daemon gate never fires.
func TestExecTrustedBynNotGated(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{})

	bynPath := "/proj/.byn"
	// Use a missing binary — exec will fail after IPC succeeds.
	_ = runExec([]string{"--", "byn-no-such-binary-zzz"}, cliScope{SourcePath: bynPath})

	calls := fd.callsFor(ipc.OpExecFetch)
	if len(calls) != 1 {
		t.Fatalf("got %d exec.fetch calls, want exactly 1 (no retry for trusted .byn)", len(calls))
	}
	var req ipc.ExecFetchReq
	requireUnmarshal(t, calls[0].Body, &req)
	if len(req.Password) != 0 {
		t.Errorf("trusted .byn exec carried password: %q (should be empty)", req.Password)
	}
}
