//go:build integration

// NU-2.1 end-to-end integration tests.
//
// Covered:
//  1. Scraper e2e: .byn with a pattern "... {{uuid}}" alias; the owner's
//     real use case: trusted → free with valid UUID; non-UUID → auth_required
//     non-TTY path.
//  2. Alias e2e: alias + {{args}} pattern free with extra args; bare pattern
//     + extra args → denied non-TTY; missing alias → not-found error with hint.
//  3. Grant display e2e: `byn trust` output shows aliases + a {{args}} warning.

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const nu21PW = "correct-horse-battery-staple-nu21"

// bootstrapNU21 starts a daemon, inits+unlocks the vault, creates a project,
// and writes a .byn file.  Returns the session, projDir, and dotPath.
func bootstrapNU21(t *testing.T, bynContent string) (*session, string, string) {
	t.Helper()
	s := bootstrapUnlocked(t)
	projDir := filepath.Join(s.dir, "nu21-proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatalf("mkdir projDir: %v", err)
	}
	dotPath := filepath.Join(projDir, ".byn")
	if err := os.WriteFile(dotPath, []byte(bynContent), 0o600); err != nil {
		t.Fatalf("write .byn: %v", err)
	}
	// Project must be created before secrets can be stored there.
	if _, _, code := s.run("", "project", "create", "nu21"); code != 0 {
		t.Fatalf("project create nu21 failed")
	}
	return s, projDir, dotPath
}

// --------------------------------------------------------------------------
// Test 1 — Scraper e2e (the owner's real use case)
//
// .byn with:
//   - alias  "scrape = /bin/echo scrape --id"
//   - action "/bin/echo scrape --id {{uuid}}"
//
// Run `byn exec scrape <valid-uuid>` → free, stdout has the UUID.
// Run `byn exec scrape not-a-uuid` non-TTY → exit nonzero (auth_required).
// --------------------------------------------------------------------------

func TestNU21_Scraper_E2E(t *testing.T) {
	bynContent := `[scope]
project = "nu21"

[exec]
env = ["DB_URL"]
actions = ["/bin/echo scrape --id {{uuid}}"]

[aliases]
scrape = "/bin/echo scrape --id"
`
	s, projDir, dotPath := bootstrapNU21(t, bynContent)

	// Store a secret in the nu21 project.
	if _, se, code := s.run("s3cret", "--project", "nu21", "put", "DB_URL"); code != 0 {
		t.Fatalf("put DB_URL: code=%d stderr=%q", code, se)
	}

	// Trust the .byn.
	// bootstrapUnlocked uses the const pw defined in scope_crud_io_test.go
	// which is "correct-horse-battery-staple" — reuse it.
	trustPW := "correct-horse-battery-staple\n"
	if _, se, code := s.runInDir(projDir, trustPW, nil, "trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust .byn: code=%d stderr=%q", code, se)
	}

	validUUID := "550e8400-e29b-41d4-a716-446655440000"

	// Trusted alias with a valid UUID → free (no password needed), stdout
	// contains the UUID (it was passed to /bin/echo).
	stdout, se, code := s.runInDir(projDir, "", nil, "exec", "scrape", validUUID)
	if code != 0 {
		t.Fatalf("exec scrape <valid-uuid>: code=%d stderr=%q stdout=%q", code, se, stdout)
	}
	if !strings.Contains(stdout, validUUID) {
		t.Errorf("exec scrape: stdout=%q, want UUID %q in output", stdout, validUUID)
	}

	// Non-UUID argument → pattern mismatch → auth_required → non-TTY exits nonzero.
	_, stderrBad, codeBad := s.runInDir(projDir, "", nil, "exec", "scrape", "not-a-uuid")
	if codeBad == 0 {
		t.Fatal("exec scrape not-a-uuid should fail (auth_required non-TTY); got exit 0")
	}
	// The stderr should mention authorization or [exec] actions.
	if !strings.Contains(stderrBad, "authorization") && !strings.Contains(stderrBad, "actions") {
		t.Errorf("non-uuid stderr should mention auth/actions:\n%s", stderrBad)
	}
}

// --------------------------------------------------------------------------
// Test 2 — Alias e2e
//
// Three sub-cases:
//   a. Alias + {{args}} pattern: free with extra args appended.
//   b. Bare pattern (no {{args}}): extra args cause mismatch → denied non-TTY.
//   c. Missing alias → not-found error with hint.
// --------------------------------------------------------------------------

func TestNU21_Alias_WithArgsPattern_Free(t *testing.T) {
	bynContent := `[scope]
project = "nu21"

[exec]
env = []
actions = ["/bin/echo run {{args}}"]

[aliases]
run = "/bin/echo run"
`
	s, projDir, dotPath := bootstrapNU21(t, bynContent)

	trustPW := "correct-horse-battery-staple\n"
	if _, se, code := s.runInDir(projDir, trustPW, nil, "trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}

	// run alias with extra args: resolved = ["/bin/echo", "run", "--verbose"]
	// → matches "/bin/echo run {{args}}" → free.
	stdout, se, code := s.runInDir(projDir, "", nil, "exec", "run", "--verbose")
	if code != 0 {
		t.Fatalf("exec alias with extra args: code=%d stderr=%q", code, se)
	}
	// /bin/echo will print all its args; "--verbose" should be in the output.
	if !strings.Contains(stdout, "--verbose") {
		t.Errorf("exec output = %q, want '--verbose' in it", stdout)
	}
}

func TestNU21_Alias_BarePattern_ExtraArgsDenied(t *testing.T) {
	bynContent := `[scope]
project = "nu21"

[exec]
env = []
actions = ["/bin/echo run"]

[aliases]
run = "/bin/echo run"
`
	s, projDir, dotPath := bootstrapNU21(t, bynContent)

	trustPW := "correct-horse-battery-staple\n"
	if _, se, code := s.runInDir(projDir, trustPW, nil, "trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}

	// run alias with extra args: resolved = ["/bin/echo", "run", "extra"]
	// → does NOT match "/bin/echo run" (strict, no {{args}}) → auth_required → non-TTY fails.
	_, stderrBad, codeBad := s.runInDir(projDir, "", nil, "exec", "run", "extra-arg")
	if codeBad == 0 {
		t.Fatal("exec run extra-arg should fail (strict pattern, no {{args}}); got exit 0")
	}
	if !strings.Contains(stderrBad, "authorization") && !strings.Contains(stderrBad, "actions") {
		t.Errorf("stderr should mention auth/actions:\n%s", stderrBad)
	}
}

func TestNU21_Alias_MissingAlias_NotFoundWithHint(t *testing.T) {
	bynContent := `[scope]
project = "nu21"

[exec]
env = []
actions = []

[aliases]
start = "/bin/echo start"
`
	s, projDir, dotPath := bootstrapNU21(t, bynContent)

	trustPW := "correct-horse-battery-staple\n"
	if _, se, code := s.runInDir(projDir, trustPW, nil, "trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}

	// Request an alias that doesn't exist.
	_, stderrMiss, codeMiss := s.runInDir(projDir, "", nil, "exec", "no-such-alias")
	if codeMiss == 0 {
		t.Fatal("exec no-such-alias should fail (not found); got exit 0")
	}
	// The error must mention the alias name and hint at available aliases.
	if !strings.Contains(stderrMiss, "no-such-alias") {
		t.Errorf("stderr should mention the alias name:\n%s", stderrMiss)
	}
	// The hint should list available aliases ("start" is defined).
	if !strings.Contains(stderrMiss, "start") && !strings.Contains(stderrMiss, "not defined") {
		t.Errorf("stderr should hint at available aliases or 'not defined':\n%s", stderrMiss)
	}
}

// --------------------------------------------------------------------------
// Test 3 — Grant display e2e
//
// `byn trust` output shows aliases in the policy summary plus a {{args}}
// warning when any action contains a tail-wildcard.
// --------------------------------------------------------------------------

func TestNU21_TrustDisplay_AliasesAndArgsWarning(t *testing.T) {
	bynContent := `[scope]
project = "nu21"

[exec]
env = []
actions = ["/bin/echo run {{args}}"]

[aliases]
run = "/bin/echo run"
build = "/bin/echo build"
`
	s, projDir, dotPath := bootstrapNU21(t, bynContent)

	trustPW := "correct-horse-battery-staple\n"
	_, stderrTrust, codeTrust := s.runInDir(projDir, trustPW, nil, "trust", "--password-stdin", dotPath)
	if codeTrust != 0 {
		t.Fatalf("trust: code=%d stderr=%q", codeTrust, stderrTrust)
	}

	// The grant display must show the aliases.
	if !strings.Contains(stderrTrust, "aliases:") {
		t.Errorf("trust output should show 'aliases:' line:\n%s", stderrTrust)
	}
	// Both aliases must appear.
	if !strings.Contains(stderrTrust, "run") {
		t.Errorf("trust output should mention alias 'run':\n%s", stderrTrust)
	}
	if !strings.Contains(stderrTrust, "build") {
		t.Errorf("trust output should mention alias 'build':\n%s", stderrTrust)
	}
	// The {{args}} warning must fire because the action contains {{args}}.
	// The trust display emits: `Warning: action "..." permits ARBITRARY extra arguments`
	if !strings.Contains(stderrTrust, "ARBITRARY extra arguments") {
		t.Errorf("trust output should warn about {{args}} (ARBITRARY extra arguments):\n%s", stderrTrust)
	}
}
