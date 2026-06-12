//go:build integration

// NU-2 end-to-end integration tests.
//
// Covered:
//  1. Actions e2e: trusted .byn with [exec] actions pinned runs free;
//     unlisted command non-TTY → exit nonzero, stderr mentions [exec] actions.
//  2. mtime re-trust + diff: trust → touch (content unchanged) → exec CHANGED
//     → `byn trust diff` exits 1 with "content identical; modification time
//     changed" → re-trust → exec works again.
//  3. Content diff e2e: modify .byn → `byn trust diff` exits 1 and prints
//     ±diff lines → re-trust → exec works.
//  4. Policy e2e: .byn with [auth] get = "none" trusted for one scope →
//     `byn get` in that scope succeeds with NO password (NU-3 session gate
//     is always active; policy overrides it); same get in ANOTHER project
//     still fails (non-TTY, no session, no password).
//  5. Malformed grant refusal: `byn trust` of an invalid-TOML .byn exits nonzero,
//     stderr names the parse problem, and the file is NOT in `byn trust list`.
//  6. v1-migration note check: not automatable with a fresh store (no v1 records);
//     skipped with an explanatory comment.

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const nu2PW = "correct-horse-battery-staple"

// bootstrapNU2 starts a daemon, inits+unlocks the vault, creates the "alpha"
// project, writes a .byn in projDir, and returns the session, projDir, and
// .byn path.  The caller is responsible for trusting the file.
func bootstrapNU2(t *testing.T, bynContent string) (*session, string, string) {
	t.Helper()
	s := bootstrapUnlocked(t)

	projDir := filepath.Join(s.dir, "nu2-proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatalf("mkdir projDir: %v", err)
	}
	dotPath := filepath.Join(projDir, ".byn")
	if err := os.WriteFile(dotPath, []byte(bynContent), 0o600); err != nil {
		t.Fatalf("write .byn: %v", err)
	}
	if _, _, code := s.run("", "project", "create", "alpha"); code != 0 {
		t.Fatalf("project create alpha failed")
	}
	return s, projDir, dotPath
}

// --------------------------------------------------------------------------
// Test 1 — Actions e2e
//
// A .byn that pins [exec] actions = ["/usr/bin/env"]:
//   - exec of the pinned command runs free (no password, no TTY needed).
//   - exec of a command NOT in the actions list fails non-TTY with nonzero
//     exit and stderr mentioning "[exec] actions".
//
// Note: the "unlisted command non-TTY" case is already tested by
// TestE2E_ExecFetch_UnlistedCommandNonTTY in execfetch_test.go; this test
// asserts both halves together so the actions semantics are documented as
// one end-to-end story.
// --------------------------------------------------------------------------

func TestNU2_Actions_E2E(t *testing.T) {
	bynContent := "[scope]\nproject = \"alpha\"\n[exec]\nenv = [\"DB_URL\"]\nactions = [\"/usr/bin/env\"]\n"
	s, projDir, dotPath := bootstrapNU2(t, bynContent)

	if _, _, code := s.runInDir(projDir, "s3cret", nil, "put", "DB_URL"); code != 0 {
		t.Fatalf("put DB_URL failed")
	}
	if _, se, code := s.runInDir(projDir, nu2PW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}

	// Pinned command runs free.
	stdout, se, code := s.runInDir(projDir, "", nil, "exec", "--", "/usr/bin/env")
	if code != 0 {
		t.Fatalf("exec pinned /usr/bin/env: code=%d stderr=%q", code, se)
	}
	if !strings.Contains(stdout, "DB_URL=s3cret") {
		t.Errorf("exec did not inject DB_URL:\n%s", stdout)
	}

	// Unlisted command fails non-TTY with [exec] actions in stderr.
	_, stderr, code := s.runInDir(projDir, "", nil, "exec", "--", "/usr/bin/true")
	if code == 0 {
		t.Fatal("exec of unlisted command should fail; got code 0")
	}
	if !strings.Contains(stderr, "[exec] actions") {
		t.Errorf("stderr should mention '[exec] actions' for unlisted command:\n%s", stderr)
	}
}

// --------------------------------------------------------------------------
// Test 2 — mtime re-trust + diff
//
// trust a .byn → touch the file (content unchanged) → exec fails with CHANGED
// → `byn trust diff <path>` exits 1 and prints "content identical; modification
// time changed" → re-trust → exec works again.
// --------------------------------------------------------------------------

func TestNU2_MtimeRetrust_Diff(t *testing.T) {
	bynContent := "[scope]\nproject = \"alpha\"\n[exec]\nenv = [\"DB_URL\"]\nactions = [\"/usr/bin/env\"]\n"
	s, projDir, dotPath := bootstrapNU2(t, bynContent)

	if _, _, code := s.runInDir(projDir, "v1", nil, "put", "DB_URL"); code != 0 {
		t.Fatalf("put DB_URL failed")
	}
	if _, se, code := s.runInDir(projDir, nu2PW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}

	// First exec must succeed.
	if _, se, code := s.runInDir(projDir, "", nil, "exec", "--", "/usr/bin/env"); code != 0 {
		t.Fatalf("exec before touch: code=%d stderr=%q", code, se)
	}

	// Touch the file: update mtime without changing content.
	// Sleep 10ms first so the OS has distinct mtime granularity.
	time.Sleep(10 * time.Millisecond)
	now := time.Now()
	if err := os.Chtimes(dotPath, now, now); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Exec must now fail with CHANGED (mtime mismatch).
	_, stderr, code := s.runInDir(projDir, "", nil, "exec", "--", "/usr/bin/env")
	if code == 0 {
		t.Fatal("exec after touch should fail; got code 0")
	}
	if !strings.Contains(stderr, "CHANGED") {
		t.Errorf("stderr should mention CHANGED after touch:\n%s", stderr)
	}

	// `byn trust diff` must exit 1 and mention "content identical" / "modification time".
	diffStdout, diffStderr, diffCode := s.run("", "trust", "diff", dotPath)
	_ = diffStdout
	if diffCode == 0 {
		t.Fatal("byn trust diff should exit 1 for mtime-only change; got 0")
	}
	combined := diffStdout + diffStderr
	if !strings.Contains(combined, "content identical") || !strings.Contains(combined, "modification time") {
		t.Errorf("byn trust diff output should mention 'content identical' and 'modification time':\n%s", combined)
	}

	// Re-trust → exec works again.
	if _, se, code := s.runInDir(projDir, nu2PW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("re-trust after mtime: code=%d stderr=%q", code, se)
	}
	if _, se, code := s.runInDir(projDir, "", nil, "exec", "--", "/usr/bin/env"); code != 0 {
		t.Fatalf("exec after re-trust: code=%d stderr=%q", code, se)
	}
}

// --------------------------------------------------------------------------
// Test 3 — Content diff e2e
//
// Modify the .byn → `byn trust diff` exits 1 and shows +/- lines in stdout
// → re-trust → exec works.
// --------------------------------------------------------------------------

func TestNU2_ContentDiff_E2E(t *testing.T) {
	originalContent := "[scope]\nproject = \"alpha\"\n[exec]\nenv = [\"DB_URL\"]\nactions = [\"/usr/bin/env\"]\n"
	s, projDir, dotPath := bootstrapNU2(t, originalContent)

	if _, _, code := s.runInDir(projDir, "val1", nil, "put", "DB_URL"); code != 0 {
		t.Fatalf("put DB_URL failed")
	}
	if _, se, code := s.runInDir(projDir, nu2PW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}

	// Modify the .byn (add a comment — content change).
	modifiedContent := originalContent + "# modified\n"
	if err := os.WriteFile(dotPath, []byte(modifiedContent), 0o600); err != nil {
		t.Fatalf("write modified .byn: %v", err)
	}

	// `byn trust diff` must exit 1 and print diff lines.
	diffStdout, diffStderr, diffCode := s.run("", "trust", "diff", dotPath)
	if diffCode == 0 {
		t.Fatal("byn trust diff should exit 1 for content change; got 0")
	}
	// Unified diff lines should appear in stdout.
	if !strings.Contains(diffStdout, "+") {
		t.Errorf("byn trust diff stdout should contain diff lines ('+' for additions):\nstdout=%s\nstderr=%s",
			diffStdout, diffStderr)
	}
	if !strings.Contains(diffStdout+diffStderr, "re-trust") {
		t.Errorf("byn trust diff output should mention 're-trust':\nstdout=%s\nstderr=%s",
			diffStdout, diffStderr)
	}

	// Re-trust with the new content → exec works.
	if _, se, code := s.runInDir(projDir, nu2PW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("re-trust after content change: code=%d stderr=%q", code, se)
	}
	if _, se, code := s.runInDir(projDir, "", nil, "exec", "--", "/usr/bin/env"); code != 0 {
		t.Fatalf("exec after re-trust: code=%d stderr=%q", code, se)
	}
}

// --------------------------------------------------------------------------
// Test 4 — Policy e2e
//
// The NU-3 session gate is always active. A .byn with [auth] get = "none"
// trusted for scope "alpha" → `byn get DB_URL` in that scope succeeds with
// NO password (non-TTY, no --password-stdin).  A `byn get` in a DIFFERENT
// project without a session still fails (non-TTY, no password supplied).
// --------------------------------------------------------------------------

func TestNU2_Policy_GetNone_E2E(t *testing.T) {
	s := newSession(t)

	if _, se, code := s.run("", "daemon", "start"); code != 0 {
		t.Fatalf("daemon start: code=%d stderr=%q", code, se)
	}
	t.Cleanup(s.stopDaemon)

	if _, _, code := s.run(nu2PW, "init", "--password-stdin"); code != 0 {
		t.Fatalf("init failed")
	}
	if _, _, code := s.run(nu2PW, "unlock", "--password-stdin"); code != 0 {
		t.Fatalf("unlock failed")
	}

	// Create the "alpha" project and seed a secret.
	if _, _, code := s.run("", "project", "create", "alpha"); code != 0 {
		t.Fatalf("project create alpha failed")
	}
	if _, se, code := s.run("s3cret-db", "--project", "alpha", "put", "DB_URL"); code != 0 {
		t.Fatalf("put DB_URL in alpha: code=%d stderr=%q", code, se)
	}
	// Seed the default project too.
	if _, se, code := s.run("other-val", "put", "OTHER_KEY"); code != 0 {
		t.Fatalf("put OTHER_KEY in default: code=%d stderr=%q", code, se)
	}

	// Write a .byn for the alpha scope with [auth] get = "none".
	alphaDir := filepath.Join(s.dir, "alpha-proj")
	if err := os.MkdirAll(alphaDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dotPath := filepath.Join(alphaDir, ".byn")
	bynContent := "[scope]\nproject = \"alpha\"\n[auth]\nget = \"none\"\n"
	if err := os.WriteFile(dotPath, []byte(bynContent), 0o600); err != nil {
		t.Fatalf("write .byn: %v", err)
	}

	// Trust it (always requires the master password).
	if _, se, code := s.runInDir(alphaDir, nu2PW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust alpha .byn: code=%d stderr=%q", code, se)
	}

	// `byn get DB_URL` in the alpha scope: should succeed WITHOUT any password
	// because [auth] get = "none" in the trusted .byn makes this op completely
	// free — no session or password required for this specific scope.
	stdout, se, code := s.runInDir(alphaDir, "", nil, "get", "DB_URL")
	if code != 0 {
		t.Fatalf("get DB_URL in alpha scope (should be free via [auth] get=none): code=%d stderr=%q",
			code, se)
	}
	if strings.TrimSpace(stdout) != "s3cret-db" {
		t.Errorf("get DB_URL = %q, want s3cret-db", strings.TrimSpace(stdout))
	}

	// `byn get OTHER_KEY` in the default scope — lock the vault first to clear
	// all active sessions (NU-3: lock invalidates session tokens). Without a
	// session and without a password, the NU-3 auth gate returns auth_required
	// and the command fails.
	if _, _, lockCode := s.run("", "lock"); lockCode != 0 {
		t.Fatalf("lock: code=%d", lockCode)
	}
	_, stderrOther, codeOther := s.run("", "get", "OTHER_KEY")
	if codeOther == 0 {
		t.Fatal("get in default scope (locked vault, no session, no password) should fail; got 0")
	}
	_ = stderrOther // non-zero exit is the assertion; exact message may vary
}

// --------------------------------------------------------------------------
// Test 5 — Malformed grant refusal
//
// `byn trust` of an invalid-TOML .byn exits nonzero, stderr names the parse
// problem, and the file is NOT subsequently in `byn trust list`.
// --------------------------------------------------------------------------

func TestNU2_MalformedByn_TrustRefused(t *testing.T) {
	s := bootstrapUnlocked(t)

	malformedDir := filepath.Join(s.dir, "malformed-proj")
	if err := os.MkdirAll(malformedDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dotPath := filepath.Join(malformedDir, ".byn")
	// Write deliberately invalid TOML.
	if err := os.WriteFile(dotPath, []byte("[scope\nproject = \"alpha\"\n"), 0o600); err != nil {
		t.Fatalf("write malformed .byn: %v", err)
	}

	// `byn trust` must exit nonzero.
	_, stderr, code := s.runInDir(malformedDir, nu2PW+"\n", nil,
		"trust", "--password-stdin", dotPath)
	if code == 0 {
		t.Fatal("trust of malformed .byn should fail; got code 0")
	}
	// stderr must name the parse problem.
	if !strings.Contains(stderr, "parse") && !strings.Contains(stderr, "toml") &&
		!strings.Contains(stderr, "TOML") && !strings.Contains(stderr, "invalid") &&
		!strings.Contains(stderr, "malformed") && !strings.Contains(stderr, "syntax") {
		t.Errorf("stderr should describe the parse error:\n%s", stderr)
	}

	// The file must NOT appear in `byn trust list`.
	listOut, _, listCode := s.run("", "trust", "list")
	if listCode != 0 {
		t.Fatalf("trust list failed: code=%d", listCode)
	}
	if strings.Contains(listOut, dotPath) || strings.Contains(listOut, "malformed-proj") {
		t.Errorf("malformed .byn should not be in trust list:\n%s", listOut)
	}
}

// --------------------------------------------------------------------------
// Test 6 — v1-migration note check
//
// This test cannot be automated: a fresh store has no v1 trust records, so
// there is nothing to migrate. The migration behaviour (v1 records showing
// as "stale" → guided re-trust) is documented in docs/security.md §NU-2.
// Skipped here intentionally.
// --------------------------------------------------------------------------

// (intentionally omitted — see docs/security.md for v1 migration guidance)
