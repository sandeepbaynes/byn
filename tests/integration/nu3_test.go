//go:build integration

// NU-3 end-to-end integration tests.
//
// Covered:
//  1. Cross-terminal denial: client A unlocks (session present); client B has
//     NO session token — get returns auth_required even though the vault is
//     unlocked. This is the "no-global-unlock" proof at the socket level.
//     Tests 1–3 and parts of 4 drive raw ipc.Client connections because
//     non-TTY integration tests never have a session file (ttyRdev()==0 ⇒
//     byn unlock writes no session).  The ipc.Client approach captures the
//     session token from CallAndCaptureSession and carries it explicitly via
//     c.Session — proving the server-side contract without needing a PTY.
//  2. Token invalidation: end a session via OpSessionEnd → subsequent get with
//     the old token returns auth_required.
//  3. TTL/idle expiry: unlock with a short session_ttl config; wait past TTL;
//     get returns auth_required.
//  4. Batch single-auth (export): with an active session satisfying every get,
//     export N entries with one --password-stdin invocation (the password is
//     acquired once and reused for all per-entry gets — "batch single auth").
//  5. Exec matrix: trusted .byn with pinned action runs free (no session);
//     ad-hoc exec without session/creds fails auth_required.
//  6. v3→v4 schema migration: construct a v3-style vault on disk (byn init
//     then downgrade schema_version + rename column via SQL), run byn unlock →
//     the daemon migrates and unlocks successfully.

package integration

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite" // register "sqlite" driver

	"github.com/sandeepbaynes/byn/internal/daemon"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

const nu3PW = "correct-horse-battery-staple-nu3"

// ------------------------------------------------------------------ helpers

// bootstrapNU3 starts a daemon, inits+unlocks the vault, and returns the
// session with s.pw set to nu3PW.  Unlike bootstrapUnlocked it uses the
// nu3PW constant so tests in this file share a known password.
//
// Non-TTY note: ttyRdev()==0 means byn unlock writes no session file.
// Tests that need to prove the session contract drive raw ipc.Client
// connections instead (see ipcUnlock below).
func bootstrapNU3(t *testing.T) *session {
	t.Helper()
	s := newSession(t)
	if _, _, code := s.run("", "daemon", "start"); code != 0 {
		t.Fatalf("daemon start failed")
	}
	t.Cleanup(s.stopDaemon)
	if _, _, code := s.run(nu3PW, "init", "--password-stdin"); code != 0 {
		t.Fatalf("init failed")
	}
	if _, _, code := s.run(nu3PW, "unlock", "--password-stdin"); code != 0 {
		t.Fatalf("unlock failed")
	}
	s.pw = nu3PW
	return s
}

// ipcUnlock unlocks the default vault via a raw ipc.Client and returns a
// client with c.Session set to the minted session token.  This is how
// integration tests prove session-level contracts without a PTY:
// CallAndCaptureSession returns the token from the response envelope, and
// subsequent calls on the same client carry it via c.Session — identical
// to what a terminal-attached byn unlock does.
func ipcUnlock(t *testing.T, s *session, pw string) *ipc.Client {
	t.Helper()
	sockPath := filepath.Join(s.dir, daemon.SocketFilename)
	c := ipc.NewClient(sockPath)
	c.Timeout = 30 * time.Second
	var resp ipc.VaultUnlockResp
	tok, err := c.CallAndCaptureSession(
		ipc.OpVaultUnlock,
		ipc.VaultUnlockReq{Name: "default", Password: []byte(pw)},
		&resp, nil,
	)
	if err != nil {
		t.Fatalf("ipcUnlock: %v", err)
	}
	if len(tok) == 0 {
		t.Fatal("ipcUnlock: daemon returned empty session token")
	}
	c.Session = tok
	return c
}

// vaultDBPath returns the path to the default vault's SQLite database in the
// given BYN_DIR.
func vaultDBPath(bynDir string) string {
	return filepath.Join(bynDir, "vaults", "default", "vault.db")
}

// ------------------------------------------------------------------ Test 1: cross-terminal denial

// TestNU3_CrossTerminalDenial proves the "no-global-unlock" invariant at the
// integration level.
//
// We simulate two independent callers via two ipc.Client connections:
//   - Client A: ipcUnlock mints a session and sets c.Session → get succeeds.
//   - Client B: fresh ipc.Client with NO session token → get returns
//     auth_required even though the vault is unlocked daemon-side.
//
// True PTY separation is overkill here — the TTY device check is already
// verified by the daemon unit tests in internal/daemon/nu3_authz_test.go
// (TestNU3_NoGlobalUnlock).  What this test adds is the end-to-end wire proof
// that the daemon's session gate operates per-connection, not per-vault-state.
func TestNU3_CrossTerminalDenial(t *testing.T) {
	s := bootstrapNU3(t)

	// Store a value (insert is free — new name, no auth gate).
	if _, se, code := s.run("val-A", "put", "CROSS_KEY"); code != 0 {
		t.Fatalf("put CROSS_KEY: code=%d stderr=%q", code, se)
	}

	// Client A: ipc.Client with session from ipcUnlock — get must succeed.
	cA := ipcUnlock(t, s, nu3PW)
	var getResp ipc.GetResp
	if err := cA.Call(ipc.OpGet, ipc.GetReq{Name: "CROSS_KEY"}, &getResp); err != nil {
		t.Fatalf("client A get (session present): %v", err)
	}
	if string(getResp.Value) != "val-A" {
		t.Errorf("client A get = %q, want val-A", getResp.Value)
	}

	// Client B: fresh client with NO session token — get must return auth_required.
	sockPath := filepath.Join(s.dir, daemon.SocketFilename)
	cB := ipc.NewClient(sockPath)
	cB.Timeout = 30 * time.Second
	// cB.Session is intentionally nil — no session token for client B.
	err := cB.Call(ipc.OpGet, ipc.GetReq{Name: "CROSS_KEY"}, &getResp)
	if err == nil {
		t.Fatal("client B get without session should fail (no global unlock); got nil error")
	}
	var ipcErr *ipc.ErrResponse
	if !errors.As(err, &ipcErr) || ipcErr.Code != ipc.CodeAuthRequired {
		t.Errorf("client B get: err = %v, want CodeAuthRequired", err)
	}
}

// ------------------------------------------------------------------ Test 2: token invalidation

// TestNU3_TokenInvalidation proves that after OpSessionEnd the session token
// no longer satisfies the auth gate.
func TestNU3_TokenInvalidation(t *testing.T) {
	s := bootstrapNU3(t)

	// Insert is free — no session needed.
	if _, se, code := s.run("secret-val", "put", "INV_KEY"); code != 0 {
		t.Fatalf("put INV_KEY: code=%d stderr=%q", code, se)
	}

	// Obtain a session via ipc.Client unlock.
	c := ipcUnlock(t, s, nu3PW)

	// Confirm session works.
	var getResp ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "INV_KEY"}, &getResp); err != nil {
		t.Fatalf("get with active session: %v", err)
	}
	if string(getResp.Value) != "secret-val" {
		t.Errorf("get = %q, want secret-val", getResp.Value)
	}

	// End the session (vault stays unlocked for other callers).
	if err := c.Call(ipc.OpSessionEnd, ipc.SessionEndReq{}, &ipc.SessionEndResp{}); err != nil {
		t.Fatalf("OpSessionEnd: %v", err)
	}

	// Get with the same (now-revoked) session token must fail.
	err := c.Call(ipc.OpGet, ipc.GetReq{Name: "INV_KEY"}, &getResp)
	if err == nil {
		t.Fatal("get after session end should fail; got nil error")
	}
	var ipcErr *ipc.ErrResponse
	if !errors.As(err, &ipcErr) || ipcErr.Code != ipc.CodeAuthRequired {
		t.Errorf("post-invalidation get: err = %v, want CodeAuthRequired", err)
	}
}

// ------------------------------------------------------------------ Test 3: TTL/idle expiry

// TestNU3_SessionTTLExpiry proves that a session with a short TTL expires and
// causes subsequent calls to return auth_required.
//
// We configure session_ttl=1s in ~/.byn/config before starting the daemon,
// then unlock via ipc.Client (to capture the token), wait 2s for the TTL to
// elapse, and verify get fails.
func TestNU3_SessionTTLExpiry(t *testing.T) {
	s := newSession(t)

	// Write a short TTL config before starting the daemon.
	cfgBody := "[security]\nsession_ttl = \"1s\"\n"
	cfgPath := filepath.Join(s.dir, "config")
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, _, code := s.run("", "daemon", "start"); code != 0 {
		t.Fatalf("daemon start failed")
	}
	t.Cleanup(s.stopDaemon)

	if _, _, code := s.run(nu3PW, "init", "--password-stdin"); code != 0 {
		t.Fatalf("init failed")
	}
	if _, _, code := s.run(nu3PW, "unlock", "--password-stdin"); code != 0 {
		t.Fatalf("unlock failed")
	}
	s.pw = nu3PW

	// Store a value (insert is free).
	if _, se, code := s.run("ttl-val", "put", "TTL_KEY"); code != 0 {
		t.Fatalf("put TTL_KEY: code=%d stderr=%q", code, se)
	}

	// Obtain a session via ipc.Client unlock.
	c := ipcUnlock(t, s, nu3PW)

	// Confirm session works before expiry.
	var getResp ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "TTL_KEY"}, &getResp); err != nil {
		t.Fatalf("get before TTL expiry: %v", err)
	}
	if string(getResp.Value) != "ttl-val" {
		t.Errorf("get before expiry = %q, want ttl-val", getResp.Value)
	}

	// Wait for the 1s TTL to elapse (plus a small buffer).
	time.Sleep(2 * time.Second)

	// Session is expired.  Get with the same token must fail.
	err := c.Call(ipc.OpGet, ipc.GetReq{Name: "TTL_KEY"}, &getResp)
	if err == nil {
		t.Fatal("get after TTL expiry should fail; got nil error")
	}
	var ipcErr *ipc.ErrResponse
	if !errors.As(err, &ipcErr) || ipcErr.Code != ipc.CodeAuthRequired {
		t.Errorf("post-expiry get: err = %v, want CodeAuthRequired", err)
	}
}

// ------------------------------------------------------------------ Test 4: batch single-auth (export)

// TestNU3_BatchExportSingleAuth proves that export with --password-stdin
// requires one credential for all N entries — the password is acquired once
// on the first auth_required and reused for every subsequent get in the loop.
// This is the "batch single auth" contract: the agent supplies credentials
// once and all values flow without re-prompting.
func TestNU3_BatchExportSingleAuth(t *testing.T) {
	s := bootstrapNU3(t)

	// Store several values (inserts are free — new names, no auth gate).
	keys := []string{"ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO"}
	for _, k := range keys {
		if _, se, code := s.run("val-"+k, "put", k); code != 0 {
			t.Fatalf("put %s: code=%d stderr=%q", k, code, se)
		}
	}

	// Export with --password-stdin: password is supplied once via stdin;
	// the export loop acquires it on first auth_required and reuses it for
	// all subsequent gets without re-prompting.  This exercises the
	// "batch single auth" code path in cmd_export.go.
	stdout, stderr, code := s.runPW("", "export", "--password-stdin", "--format", "env")
	if code != 0 {
		t.Fatalf("export with --password-stdin: code=%d stderr=%q", code, stderr)
	}
	for _, k := range keys {
		if !strings.Contains(stdout, k+"=val-"+k) {
			t.Errorf("export missing %s=val-%s:\n%s", k, k, stdout)
		}
	}
}

// se is an identity helper to let the inline se(stderr) idiom work in
// t.Fatalf calls where the variable 'stderr' might shadow.
func se(s string) string { return s }

// ------------------------------------------------------------------ Test 5: exec matrix

// TestNU3_ExecMatrix_PinnedFree proves that an [exec] actions-pinned command
// runs without any session or password (the .byn trust contract, not the
// session gate, authorizes exec).
func TestNU3_ExecMatrix_PinnedFree(t *testing.T) {
	bynContent := "[scope]\nproject = \"nu3exec\"\n[exec]\nenv = [\"EXEC_SECRET\"]\nactions = [\"/usr/bin/env\"]\n"
	s := bootstrapNU3(t)

	projDir := filepath.Join(s.dir, "nu3exec-proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatalf("mkdir projDir: %v", err)
	}
	dotPath := filepath.Join(projDir, ".byn")
	if err := os.WriteFile(dotPath, []byte(bynContent), 0o600); err != nil {
		t.Fatalf("write .byn: %v", err)
	}
	if _, _, code := s.run("", "project", "create", "nu3exec"); code != 0 {
		t.Fatalf("project create nu3exec failed")
	}
	if _, se, code := s.run("exec-secret-val", "--project", "nu3exec", "put", "EXEC_SECRET"); code != 0 {
		t.Fatalf("put EXEC_SECRET: code=%d stderr=%q", code, se)
	}
	if _, se, code := s.runInDir(projDir, nu3PW+"\n", nil, "trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}

	// After trust, remove the sessions directory so the exec runs without any
	// active session. Pinned actions must work session-free.
	sessDir := filepath.Join(s.dir, "sessions")
	if err := os.RemoveAll(sessDir); err != nil {
		t.Fatalf("remove sessions: %v", err)
	}

	// Pinned command (/usr/bin/env) runs free even without a session.
	stdout, se2, code := s.runInDir(projDir, "", nil, "exec", "--", "/usr/bin/env")
	if code != 0 {
		t.Fatalf("exec pinned (no session): code=%d stderr=%q", code, se2)
	}
	if !strings.Contains(stdout, "EXEC_SECRET=exec-secret-val") {
		t.Errorf("exec did not inject EXEC_SECRET:\n%s", stdout)
	}
}

// TestNU3_ExecMatrix_AdHocNoSessionFails proves that ad-hoc exec (no .byn)
// without a session fails with auth_required in a non-TTY context.
func TestNU3_ExecMatrix_AdHocNoSessionFails(t *testing.T) {
	s := bootstrapNU3(t)

	// Remove sessions so the CLI has no token to send.
	sessDir := filepath.Join(s.dir, "sessions")
	if err := os.RemoveAll(sessDir); err != nil {
		t.Fatalf("remove sessions: %v", err)
	}

	// Ad-hoc exec (no .byn in the tmpdir, no session) → should fail.
	tmpDir := t.TempDir()
	_, stderr, code := s.runInDir(tmpDir, "", nil, "exec", "--", "/usr/bin/true")
	if code == 0 {
		t.Fatal("ad-hoc exec without session should fail; got code 0")
	}
	// The error must communicate that auth is required.
	if !strings.Contains(stderr, "auth") && !strings.Contains(stderr, "password") &&
		!strings.Contains(stderr, "unlock") && !strings.Contains(stderr, "session") {
		t.Errorf("ad-hoc exec stderr should mention auth/password/unlock:\n%s", stderr)
	}
}

// ------------------------------------------------------------------ Test 6: v3→v4 schema migration

// TestNU3_SchemaV3ToV4Migration constructs a v3-style vault by running byn
// init (which creates a v4 vault), then downgrading its schema back to v3
// via direct SQL, and finally running byn unlock to trigger the migration.
// The test verifies that:
//
//	(a) unlock succeeds (migration ran transparently), and
//	(b) a subsequent put+get round-trip succeeds.
//
// This exercises the migrateV3toV4 code path through the full daemon stack.
// We use a STOPPED daemon for the SQL manipulation (safe: the daemon is
// not running, no WAL contention), then restart it.
func TestNU3_SchemaV3ToV4Migration(t *testing.T) {
	s := newSession(t)

	// Init and unlock once to create the v4 vault on disk.
	if _, _, code := s.run("", "daemon", "start"); code != 0 {
		t.Fatalf("daemon start (init): failed")
	}
	if _, _, code := s.run(nu3PW, "init", "--password-stdin"); code != 0 {
		t.Fatalf("init failed")
	}
	if _, _, code := s.run(nu3PW, "unlock", "--password-stdin"); code != 0 {
		t.Fatalf("initial unlock failed")
	}
	s.pw = nu3PW
	// Store a value before downgrade so we can verify it survives.
	// Insert is free — new name, no auth gate.
	if _, se, code := s.run("migrate-val", "put", "MIGRATE_KEY"); code != 0 {
		t.Fatalf("pre-downgrade put: code=%d stderr=%q", code, se)
	}
	// Lock and stop so we can modify the DB safely.
	if _, _, _ = s.run("", "lock"); true {
	}
	s.stopDaemon()

	// Downgrade the vault DB from v4 to v3:
	//   1. Rename sha256_hmac → sha256_plain (reverse of the migration).
	//   2. Set schema_version = 3.
	dbPath := vaultDBPath(s.dir)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open vault.db for downgrade: %v", err)
	}
	downgradeStmts := []string{
		`ALTER TABLE file_meta RENAME COLUMN sha256_hmac TO sha256_plain`,
		`UPDATE meta SET value = '3' WHERE key = 'schema_version'`,
	}
	for _, stmt := range downgradeStmts {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			t.Fatalf("downgrade SQL %q: %v", stmt, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db after downgrade: %v", err)
	}

	// Restart the daemon. It will see schema_version=3 on next vault open
	// and run migrateV3toV4 transparently.
	if _, _, code := s.run("", "daemon", "start"); code != 0 {
		t.Fatalf("daemon restart after downgrade: failed")
	}
	t.Cleanup(s.stopDaemon)

	// Unlock triggers the schema migration.
	_, se2, code := s.run(nu3PW, "unlock", "--password-stdin")
	if code != 0 {
		t.Fatalf("unlock after v3→v4 migration: code=%d stderr=%q", code, se2)
	}

	// Verify the value stored before downgrade is still readable.
	// Non-TTY: use --password-stdin for this auth-gated get.
	stdout, se3, code := s.runPW("", "get", "--password-stdin", "MIGRATE_KEY")
	if code != 0 {
		t.Fatalf("get MIGRATE_KEY post-migration: code=%d stderr=%q", code, se3)
	}
	if strings.TrimSpace(stdout) != "migrate-val" {
		t.Errorf("post-migration get = %q, want migrate-val", strings.TrimSpace(stdout))
	}
}
