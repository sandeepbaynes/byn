//go:build integration

// NU-1 end-to-end integration tests: exec.fetch trust gate, [exec] env
// allowlist, NU-3 session auth gate, cred-leak assertion, and locked-exec denial.
package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pw is the vault master password used throughout these tests.
const execfetchPW = "correct-horse-battery-staple"

// bootstrapExecFetch starts a daemon, inits and unlocks the vault, then
// creates a project directory containing a .byn file with a [scope] pointing
// at "alpha" and an [exec] env allowlist.  It returns the session, the project
// dir, and the path to the .byn file.  The caller is responsible for trusting
// the file before running exec.
func bootstrapExecFetch(t *testing.T, bynContent string) (*session, string, string) {
	t.Helper()
	s := bootstrapUnlocked(t)

	projDir := filepath.Join(s.dir, "execfetch-proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatalf("mkdir projDir: %v", err)
	}

	dotPath := filepath.Join(projDir, ".byn")
	if err := os.WriteFile(dotPath, []byte(bynContent), 0o600); err != nil {
		t.Fatalf("write .byn: %v", err)
	}

	// Create the "alpha" project so exec finds a valid scope.
	if _, _, code := s.run("", "project", "create", "alpha"); code != 0 {
		t.Fatalf("project create alpha: code %d", code)
	}

	return s, projDir, dotPath
}

// --------------------------------------------------------------------------
// Test 1 — Allowlist e2e
//
// put DB_URL=s3cret-db and EXTRA=s3cret-extra → .byn allows only DB_URL →
// after trust, `byn exec -- env` injects DB_URL but NOT EXTRA.
// --------------------------------------------------------------------------

func TestE2E_ExecFetch_AllowlistEnforced(t *testing.T) {
	// Pin /usr/bin/env in [exec] actions so it runs re-auth-free (this test is
	// about env allowlist filtering, not the actions gate).
	bynContent := "[scope]\nproject = \"alpha\"\n[exec]\nenv = [\"DB_URL\"]\nactions = [\"/usr/bin/env\"]\n"
	s, projDir, dotPath := bootstrapExecFetch(t, bynContent)

	// Store two secrets in the alpha scope.
	if so, se, code := s.runInDir(projDir, "s3cret-db", nil, "put", "DB_URL"); code != 0 {
		t.Fatalf("put DB_URL: code=%d stdout=%q stderr=%q", code, so, se)
	}
	if so, se, code := s.runInDir(projDir, "s3cret-extra", nil, "put", "EXTRA"); code != 0 {
		t.Fatalf("put EXTRA: code=%d stdout=%q stderr=%q", code, so, se)
	}

	// Trust the .byn file (password required).
	if _, se, code := s.runInDir(projDir, execfetchPW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}

	// exec -- /usr/bin/env: child stdout must contain DB_URL and NOT EXTRA.
	stdout, se, code := s.runInDir(projDir, "", nil, "exec", "--", "/usr/bin/env")
	if code != 0 {
		t.Fatalf("exec env: code=%d stderr=%q", code, se)
	}
	if !strings.Contains(stdout, "DB_URL=s3cret-db") {
		t.Errorf("child stdout missing DB_URL=s3cret-db:\n%s", stdout)
	}
	if strings.Contains(stdout, "EXTRA") {
		t.Errorf("child stdout must NOT contain EXTRA (allowlist not applied):\n%s", stdout)
	}
}

// --------------------------------------------------------------------------
// Test 2 — Changed .byn is denied
//
// Trust the file → modify it → exec must exit 3 with CHANGED in stderr
// and hint to `byn trust`.  Audit log must show both the allowed and the
// denied exec.
// --------------------------------------------------------------------------

func TestE2E_ExecFetch_ChangedBynDenied(t *testing.T) {
	// Pin /usr/bin/env so the first exec (before tampering) succeeds re-auth-free.
	bynContent := "[scope]\nproject = \"alpha\"\n[exec]\nenv = [\"DB_URL\"]\nactions = [\"/usr/bin/env\"]\n"
	s, projDir, dotPath := bootstrapExecFetch(t, bynContent)

	if so, se, code := s.runInDir(projDir, "myval", nil, "put", "DB_URL"); code != 0 {
		t.Fatalf("put DB_URL: code=%d stdout=%q stderr=%q", code, so, se)
	}

	// Trust the original file.
	if _, se, code := s.runInDir(projDir, execfetchPW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}

	// First exec must succeed.
	if so, se, code := s.runInDir(projDir, "", nil, "exec", "--", "/usr/bin/env"); code != 0 {
		t.Fatalf("first exec (should succeed): code=%d\nstdout=%q\nstderr=%q", code, so, se)
	}

	// Tamper: append a comment line to the trusted .byn.
	f, err := os.OpenFile(dotPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open .byn for append: %v", err)
	}
	if _, err := f.WriteString("# tampered\n"); err != nil {
		f.Close()
		t.Fatalf("append tamper: %v", err)
	}
	f.Close()

	// Second exec must fail with trust_denied / CHANGED.
	_, stderr, code := s.runInDir(projDir, "", nil, "exec", "--", "/usr/bin/env")
	if code == 0 {
		t.Fatal("exec on changed .byn should fail; got code 0")
	}
	if code != exitDaemonErrCode {
		t.Errorf("exec changed .byn: code = %d, want %d", code, exitDaemonErrCode)
	}
	if !strings.Contains(stderr, "CHANGED") {
		t.Errorf("stderr should mention CHANGED:\n%s", stderr)
	}
	if !strings.Contains(stderr, "byn trust") {
		t.Errorf("stderr should mention 'byn trust' recovery:\n%s", stderr)
	}

	// Audit log must contain both the allowed exec and the denied exec.
	auditOut, _, auditCode := s.run("", "audit", "tail", "--lines", "50")
	if auditCode != 0 {
		t.Fatalf("audit tail: code=%d", auditCode)
	}
	if !strings.Contains(auditOut, "exec") {
		t.Errorf("audit log missing exec events:\n%s", auditOut)
	}
	// Both "ok" and "denied" execs should be in the audit trail.
	if !strings.Contains(auditOut, "ok") {
		t.Errorf("audit log missing 'ok' outcome (first exec):\n%s", auditOut)
	}
	if !strings.Contains(auditOut, "denied") {
		t.Errorf("audit log missing 'denied' outcome (changed-file exec):\n%s", auditOut)
	}
}

// --------------------------------------------------------------------------
// Test 3 — NU-3 session gate e2e
//
// The NU-3 session gate is always active (no flag required).
// After init+unlock:
//   - byn get with wrong password via --password-stdin: fails (exit 3)
//   - byn get with correct password via --password-stdin: succeeds
//   - trusted byn exec injects WITHOUT any password (unaffected by gate)
//   - byn list works free (no password needed)
//   - insert of a NEW name needs no password
// --------------------------------------------------------------------------

func TestE2E_PerActionAuth_E2E(t *testing.T) {
	// Start daemon with default config — the NU-3 session gate is always active.
	s := newSession(t)

	// Start the daemon.
	if _, se, code := s.run("", "daemon", "start"); code != 0 {
		t.Fatalf("daemon start: code=%d stderr=%q", code, se)
	}
	t.Cleanup(s.stopDaemon)

	// Init the vault — but do NOT unlock yet.  While the vault is locked and
	// there is no active session, the NU-3 gate rejects wrong credentials.
	if _, _, code := s.run(execfetchPW, "init", "--password-stdin"); code != 0 {
		t.Fatalf("init failed")
	}

	// --- Gate verification: wrong password fails before any session exists ---
	// byn get --password-stdin with wrong password on a locked vault (no session)
	// must return auth_required / wrong_password → exit 3.
	// Note: flag must come before the positional name arg (Go's flag package
	// stops parsing flags at the first non-flag arg).
	_, se, wcode := s.run("wrongpw\n", "get", "--password-stdin", "DB_URL")
	if wcode == 0 {
		t.Fatal("get with wrong password (locked, no session) should fail; got code 0")
	}
	if wcode != exitDaemonErrCode {
		t.Errorf("get wrong pw: code = %d, want %d; stderr=%q", wcode, exitDaemonErrCode, se)
	}

	// The rate limiter was hit once above; wait for it to clear.
	// The default backoff base is 500ms.
	time.Sleep(600 * time.Millisecond)

	// Unlock the vault — this mints a session token.  In NU-3 the session
	// satisfies the auth gate for value ops without re-supplying a password.
	if _, _, code := s.run(execfetchPW, "unlock", "--password-stdin"); code != 0 {
		t.Fatalf("unlock failed")
	}

	// Seed a known value (free insert — new name, no auth gate).
	if so, se, code := s.run("s3cret-db", "put", "DB_URL"); code != 0 {
		t.Fatalf("put DB_URL: code=%d stdout=%q stderr=%q", code, so, se)
	}

	// --- Gate verification: correct password succeeds ---
	// Non-TTY: no session is written by unlock (ttyRdev()==0).  The agent
	// workflow is --password-stdin per gated call.
	stdout, _, okcode := s.run(execfetchPW+"\n", "get", "--password-stdin", "DB_URL")
	if okcode != 0 {
		t.Fatalf("get with correct password: code=%d", okcode)
	}
	if strings.TrimSpace(stdout) != "s3cret-db" {
		t.Errorf("get value = %q, want s3cret-db", strings.TrimSpace(stdout))
	}

	// --- byn list is free (no password) ---
	listOut, _, listCode := s.run("", "list")
	if listCode != 0 {
		t.Fatalf("list (should be free): code=%d", listCode)
	}
	if !strings.Contains(listOut, "DB_URL") {
		t.Errorf("list missing DB_URL:\n%s", listOut)
	}

	// --- Insert of a NEW name is free (no auth gate on insert) ---
	if so, se2, code := s.run("newval", "put", "BRAND_NEW_KEY"); code != 0 {
		t.Fatalf("insert new key (should be free): code=%d stdout=%q stderr=%q", code, so, se2)
	}

	// --- Trusted .byn exec injects without any password ---
	// Set up a project scope and write a .byn with allowlist.
	projDir := filepath.Join(s.dir, "pa-proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dotPath := filepath.Join(projDir, ".byn")
	// Pin /usr/bin/env in [exec] actions — exec must run auth-free on a
	// matched pinned command. The .byn's own contract (pinned action = authorization)
	// is independent of the session gate.
	bynContent := "[scope]\nproject = \"default\"\n[exec]\nenv = [\"DB_URL\"]\nactions = [\"/usr/bin/env\"]\n"
	if err := os.WriteFile(dotPath, []byte(bynContent), 0o600); err != nil {
		t.Fatalf("write .byn: %v", err)
	}
	if _, se2, code := s.runInDir(projDir, execfetchPW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust .byn: code=%d stderr=%q", code, se2)
	}

	// exec via the trusted .byn injects DB_URL WITHOUT any interactive password
	// (pinned action = authorization; session gate does not apply here).
	execOut, execSe, execCode := s.runInDir(projDir, "", nil, "exec", "--", "/usr/bin/env")
	if execCode != 0 {
		t.Fatalf("exec with trusted .byn: code=%d stderr=%q", execCode, execSe)
	}
	if !strings.Contains(execOut, "DB_URL=s3cret-db") {
		t.Errorf("exec did not inject DB_URL=s3cret-db:\n%s", execOut)
	}

}

// --------------------------------------------------------------------------
// Test 4 — Cred-leak assertion
//
// After a successful exec.fetch injection, verify secret bytes do NOT appear
// in: parent env, daemon log file, byn command stderr, or any file under
// BYN_DIR except vault.db (and its WAL/SHM).
// --------------------------------------------------------------------------

func TestE2E_ExecFetch_NoCredLeak(t *testing.T) {
	const secretValue = "x7Qp-no-leak-secret-v1"
	// Pin /usr/bin/env so exec runs re-auth-free (this test is about cred-leak,
	// not the actions gate).
	bynContent := "[scope]\nproject = \"alpha\"\n[exec]\nenv = [\"SECRET_VAR\"]\nactions = [\"/usr/bin/env\"]\n"
	s, projDir, dotPath := bootstrapExecFetch(t, bynContent)

	if so, se, code := s.runInDir(projDir, secretValue, nil, "put", "SECRET_VAR"); code != 0 {
		t.Fatalf("put SECRET_VAR: code=%d stdout=%q stderr=%q", code, so, se)
	}

	// Trust and exec.
	if _, se, code := s.runInDir(projDir, execfetchPW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}
	childOut, childErr, code := s.runInDir(projDir, "", nil, "exec", "--", "/usr/bin/env")
	if code != 0 {
		t.Fatalf("exec: code=%d stderr=%q", code, childErr)
	}

	// Child stdout may contain the secret (that's the point of injection).
	if !strings.Contains(childOut, "SECRET_VAR="+secretValue) {
		t.Errorf("child stdout does not contain the injected var:\n%s", childOut)
	}

	// The parent process's environment must NOT contain the secret.
	for _, e := range os.Environ() {
		if strings.Contains(e, secretValue) {
			t.Errorf("parent env contains secret value in %q", e)
		}
	}

	// byn command stderr must not have leaked the secret.
	if strings.Contains(childErr, secretValue) {
		t.Errorf("byn exec stderr contains secret value:\n%s", childErr)
	}

	// No file under BYN_DIR (excluding vault.db / wal / shm) may contain the secret.
	assertNoSecretInDir(t, s.dir, secretValue)
}

// assertNoSecretInDir walks dir and checks that no file (except vault.db,
// .wal, and .shm files — the encrypted store) contains the plaintext secret.
func assertNoSecretInDir(t *testing.T, dir, secret string) {
	t.Helper()
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable paths
		}
		if info.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		// Skip the encrypted vault files — the secret is legitimately stored
		// there in encrypted form (the bytes may collide by chance, but the
		// meaningful test is plaintext absence elsewhere).
		if strings.HasSuffix(base, ".db") ||
			strings.HasSuffix(base, ".db-wal") ||
			strings.HasSuffix(base, ".db-shm") {
			return nil
		}
		body, rerr := os.ReadFile(path) // #nosec G304 -- test helper scanning test dir
		if rerr != nil {
			return nil // skip unreadable
		}
		if strings.Contains(string(body), secret) {
			t.Errorf("secret found in plaintext in file %s", path)
		}
		return nil
	})
	if err != nil {
		t.Logf("walk error (non-fatal): %v", err)
	}
}

// --------------------------------------------------------------------------
// Test 5 — Locked exec is denied
//
// Trust a .byn, lock the vault, then exec must exit 3 with "locked" in stderr.
// --------------------------------------------------------------------------

func TestE2E_ExecFetch_LockedExecDenied(t *testing.T) {
	bynContent := "[scope]\nproject = \"alpha\"\n[exec]\nenv = [\"DB_URL\"]\n"
	s, projDir, dotPath := bootstrapExecFetch(t, bynContent)

	if so, se, code := s.runInDir(projDir, "myval", nil, "put", "DB_URL"); code != 0 {
		t.Fatalf("put DB_URL: code=%d stdout=%q stderr=%q", code, so, se)
	}

	// Trust the .byn file.
	if _, se, code := s.runInDir(projDir, execfetchPW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}

	// Lock the vault.
	if _, se, code := s.run("", "lock"); code != 0 {
		t.Fatalf("lock: code=%d stderr=%q", code, se)
	}

	// exec on a trusted .byn with a locked vault must fail.
	_, stderr, code := s.runInDir(projDir, "", nil, "exec", "--", "/usr/bin/env")
	if code == 0 {
		t.Fatal("exec with locked vault should fail; got code 0")
	}
	if code != exitDaemonErrCode {
		t.Errorf("exec locked: code = %d, want %d", code, exitDaemonErrCode)
	}
	if !strings.Contains(stderr, "locked") {
		t.Errorf("stderr should mention vault locked:\n%s", stderr)
	}
}

// --------------------------------------------------------------------------
// Test 6 — Unlisted command non-TTY → authorization required
//
// Trust a .byn with specific [exec] actions (pinning /usr/bin/env) and then
// exec an UNLISTED command (/usr/bin/true) in a non-TTY context (no password
// available). The daemon must refuse with nonzero exit and stderr must mention
// "[exec] actions". This pins the unconditional credential check for unmatched
// commands, independent of session state.
// --------------------------------------------------------------------------

func TestE2E_ExecFetch_UnlistedCommandNonTTY(t *testing.T) {
	// Pin only /usr/bin/env; /usr/bin/true is NOT in the list.
	bynContent := "[scope]\nproject = \"alpha\"\n[exec]\nenv = [\"DB_URL\"]\nactions = [\"/usr/bin/env\"]\n"
	s, projDir, dotPath := bootstrapExecFetch(t, bynContent)

	if so, se, code := s.runInDir(projDir, "myval", nil, "put", "DB_URL"); code != 0 {
		t.Fatalf("put DB_URL: code=%d stdout=%q stderr=%q", code, so, se)
	}

	// Trust the .byn file.
	if _, se, code := s.runInDir(projDir, execfetchPW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}

	// Exec a command NOT in [exec] actions, no password → must fail.
	// Exit code is non-zero; depending on whether stdin is a TTY the CLI may
	// return exitDaemonErr (3, non-TTY path) or exitErr (1, TTY path after
	// failed prompt) — both are acceptable; we only assert nonzero.
	_, stderr, code := s.runInDir(projDir, "", nil, "exec", "--", "/usr/bin/true")
	if code == 0 {
		t.Fatal("exec of unlisted command should fail; got code 0")
	}
	if !strings.Contains(stderr, "[exec] actions") {
		t.Errorf("stderr should mention '[exec] actions':\n%s", stderr)
	}
}
