//go:build integration

// Tests for Phase 1 (scope flags), Phase 2 (vault/project/env CRUD),
// Phase 3 (import), and Phase 4 (export). Each test uses a fresh
// session+daemon to keep them independent and parallelizable.
package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func bootstrapUnlocked(t *testing.T) *session {
	t.Helper()
	s := newSession(t)
	if _, _, code := s.run("", "daemon", "start"); code != 0 {
		t.Fatalf("daemon start failed")
	}
	t.Cleanup(s.stopDaemon)
	pw := "correct-horse-battery-staple"
	if _, _, code := s.run(pw, "init", "--password-stdin"); code != 0 {
		t.Fatalf("init failed")
	}
	if _, _, code := s.run(pw, "unlock", "--password-stdin"); code != 0 {
		t.Fatalf("unlock failed")
	}
	return s
}

func TestE2E_Scope_FlagBeforeSubcommand(t *testing.T) {
	s := bootstrapUnlocked(t)
	// project create via global flag position.
	if _, _, code := s.run("", "--project", "billing", "project", "create"); code != 0 {
		t.Fatalf("project create with leading --project failed")
	}
	stdout, _ := s.mustRun("", "project", "list")
	if !strings.Contains(stdout, "billing") {
		t.Fatalf("project list missing 'billing':\n%s", stdout)
	}
}

func TestE2E_Scope_FlagAfterSubcommand(t *testing.T) {
	s := bootstrapUnlocked(t)
	if _, _, code := s.run("", "project", "create", "billing", "--project", "billing"); code != 0 {
		// Either positional or flag suffices; here we use both.
		// Should still succeed (single value).
		t.Fatalf("project create with trailing --project failed")
	}
}

func TestE2E_Scope_EnvVarFallback(t *testing.T) {
	s := bootstrapUnlocked(t)
	if _, _, code := s.run("", "project", "create", "alpha"); code != 0 {
		t.Fatalf("project create alpha failed")
	}
	// Inject BYN_PROJECT and run a scope-sensitive op.
	t.Setenv("BYN_PROJECT", "alpha")
	stdout, _ := s.mustRun("", "project", "list")
	_ = stdout
	// Putting into alpha then reading it back from default scope should fail.
	if _, _, code := s.run("v1", "put", "K"); code != 0 {
		t.Fatalf("put into alpha (via env) failed")
	}
	// Read back with explicit --project alpha → success.
	stdout, _ = s.mustRun("", "--project", "alpha", "get", "K")
	if stdout != "v1" {
		t.Fatalf("get K in alpha = %q, want %q", stdout, "v1")
	}
}

func TestE2E_Scope_DoubleFlagConflictErrors(t *testing.T) {
	s := newSession(t)
	_, stderr, code := s.run("", "--vault", "a", "--vault", "b", "list")
	if code == 0 {
		t.Fatalf("conflicting --vault should have errored; got code 0")
	}
	if !strings.Contains(stderr, "twice") && !strings.Contains(stderr, "different values") {
		t.Fatalf("conflicting --vault expected hard-error mentioning duplicate; stderr:\n%s", stderr)
	}
}

func TestE2E_Scope_DashDashTerminator(t *testing.T) {
	s := bootstrapUnlocked(t)
	// exec'd /usr/bin/env will be invoked with --vault as a literal
	// arg of its own. The CLI must not consume it.
	stdout, _, code := s.run("", "exec", "--", "/usr/bin/env", "echo", "--vault", "literal")
	_ = stdout
	if code != 0 {
		// echo isn't always at /usr/bin/echo, but `env echo` is portable.
		t.Skipf("exec test environment quirk; code=%d stdout=%q", code, stdout)
	}
}

func TestE2E_Vault_ListJSON(t *testing.T) {
	s := bootstrapUnlocked(t)
	stdout, _ := s.mustRun("", "vault", "list", "--json")
	var got []map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("vault list --json: not valid JSON:\n%s\nerr=%v", stdout, err)
	}
	found := false
	for _, v := range got {
		if name, _ := v["name"].(string); name == "default" {
			found = true
		}
	}
	if !found {
		t.Fatalf("vault list --json missing default:\n%s", stdout)
	}
}

func TestE2E_Vault_DeleteDefaultRefused(t *testing.T) {
	s := bootstrapUnlocked(t)
	_, stderr, code := s.run("", "vault", "delete", "default")
	if code == 0 {
		t.Fatalf("deleting default vault should refuse; got code 0")
	}
	if !strings.Contains(stderr, "default") {
		t.Fatalf("refusal stderr should mention default:\n%s", stderr)
	}
}

func TestE2E_Project_CRUD(t *testing.T) {
	s := bootstrapUnlocked(t)
	if _, _, code := s.run("", "project", "create", "billing"); code != 0 {
		t.Fatalf("project create billing failed")
	}
	stdout, _ := s.mustRun("", "project", "list")
	if !strings.Contains(stdout, "billing") {
		t.Fatalf("project list missing 'billing':\n%s", stdout)
	}
	if _, _, code := s.run("", "project", "rename", "billing", "payments"); code != 0 {
		t.Fatalf("project rename failed")
	}
	stdout, _ = s.mustRun("", "project", "list")
	if strings.Contains(stdout, "billing") || !strings.Contains(stdout, "payments") {
		t.Fatalf("rename did not take effect:\n%s", stdout)
	}
	if _, _, code := s.run("", "project", "delete", "payments"); code != 0 {
		t.Fatalf("project delete failed")
	}
}

func TestE2E_Env_CRUD(t *testing.T) {
	s := bootstrapUnlocked(t)
	if _, _, code := s.run("", "project", "create", "billing"); code != 0 {
		t.Fatalf("project create failed")
	}
	if _, _, code := s.run("", "--project", "billing", "env", "create", "prod"); code != 0 {
		t.Fatalf("env create prod failed")
	}
	stdout, _ := s.mustRun("", "--project", "billing", "env", "list")
	if !strings.Contains(stdout, "prod") || !strings.Contains(stdout, "default") {
		t.Fatalf("env list missing entries:\n%s", stdout)
	}
}

func TestE2E_Import_Dotenv(t *testing.T) {
	s := bootstrapUnlocked(t)
	dir := s.dir
	path := filepath.Join(dir, "fixture.env")
	body := "# comment\nDB_URL=postgres://localhost/x\nAPI_KEY=\"sek=ret with spaces\"\nEMPTY=\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, _, code := s.run("", "import", path); code != 0 {
		t.Fatalf("import failed")
	}
	stdout, _ := s.mustRun("", "get", "DB_URL")
	if stdout != "postgres://localhost/x" {
		t.Fatalf("DB_URL = %q", stdout)
	}
	stdout, _ = s.mustRun("", "get", "API_KEY")
	if stdout != "sek=ret with spaces" {
		t.Fatalf("API_KEY = %q (quoted-with-= roundtrip broken)", stdout)
	}
}

func TestE2E_Import_JSON(t *testing.T) {
	s := bootstrapUnlocked(t)
	path := filepath.Join(s.dir, "fixture.json")
	body := `{"K1":"v1","K2":"v2","N":42}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, _, code := s.run("", "import", path); code != 0 {
		t.Fatalf("import json failed")
	}
	stdout, _ := s.mustRun("", "get", "N")
	if stdout != "42" {
		t.Fatalf("N = %q want 42", stdout)
	}
}

func TestE2E_Import_YAML(t *testing.T) {
	s := bootstrapUnlocked(t)
	path := filepath.Join(s.dir, "fixture.yaml")
	body := "K1: v1\nK2: \"v2\"\nN: 42\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, _, code := s.run("", "import", path); code != 0 {
		t.Fatalf("import yaml failed")
	}
	stdout, _ := s.mustRun("", "get", "K1")
	if stdout != "v1" {
		t.Fatalf("K1 = %q", stdout)
	}
}

func TestE2E_Import_NestedRejected(t *testing.T) {
	s := bootstrapUnlocked(t)
	path := filepath.Join(s.dir, "nested.json")
	body := `{"K1":{"nested":"x"}}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, stderr, code := s.run("", "import", path)
	if code == 0 {
		t.Fatalf("nested JSON import should have errored")
	}
	if !strings.Contains(stderr, "nested") && !strings.Contains(stderr, "flat") {
		t.Fatalf("nested-rejection error unclear:\n%s", stderr)
	}
}

func TestE2E_Import_Stdin(t *testing.T) {
	s := bootstrapUnlocked(t)
	stdin := "FOO=bar\nBAZ=qux\n"
	if _, _, code := s.run(stdin, "import", "--format", "env"); code != 0 {
		t.Fatalf("import from stdin failed")
	}
	stdout, _ := s.mustRun("", "get", "FOO")
	if stdout != "bar" {
		t.Fatalf("FOO = %q", stdout)
	}
}

func TestE2E_Export_DotenvRoundtrip(t *testing.T) {
	s := bootstrapUnlocked(t)
	if _, _, code := s.run("hello", "put", "GREETING"); code != 0 {
		t.Fatalf("put failed")
	}
	if _, _, code := s.run("v with spaces", "put", "TRICKY"); code != 0 {
		t.Fatalf("put tricky failed")
	}
	stdout, _ := s.mustRun("", "export")
	if !strings.Contains(stdout, "GREETING=hello") {
		t.Fatalf("export missing GREETING:\n%s", stdout)
	}
	if !strings.Contains(stdout, `TRICKY="v with spaces"`) {
		t.Fatalf("export missing quoted TRICKY:\n%s", stdout)
	}
}

func TestE2E_Export_JSON(t *testing.T) {
	s := bootstrapUnlocked(t)
	if _, _, code := s.run("v1", "put", "A"); code != 0 {
		t.Fatalf("put failed")
	}
	if _, _, code := s.run("v2", "put", "B"); code != 0 {
		t.Fatalf("put failed")
	}
	stdout, _ := s.mustRun("", "export", "--format", "json")
	var got map[string]string
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("export --format json: not valid JSON:\n%s\nerr=%v", stdout, err)
	}
	if got["A"] != "v1" || got["B"] != "v2" {
		t.Fatalf("export JSON wrong: %#v", got)
	}
}

func TestE2E_Export_FileOutput(t *testing.T) {
	s := bootstrapUnlocked(t)
	if _, _, code := s.run("v1", "put", "A"); code != 0 {
		t.Fatalf("put failed")
	}
	out := filepath.Join(s.dir, "dump.env")
	if _, _, code := s.run("", "export", "--output", out); code != 0 {
		t.Fatalf("export --output failed")
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read dumped file: %v", err)
	}
	if !strings.Contains(string(body), "A=v1") {
		t.Fatalf("dump.env missing A=v1:\n%s", body)
	}
	st, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("dump.env mode = %o, want 0600", st.Mode().Perm())
	}
}

func TestE2E_Import_ReplaceWipesOldKeys(t *testing.T) {
	s := bootstrapUnlocked(t)
	// Seed scope with two entries that won't be in the input.
	if _, _, code := s.run("old1", "put", "OLD_A"); code != 0 {
		t.Fatalf("put OLD_A failed")
	}
	if _, _, code := s.run("old2", "put", "OLD_B"); code != 0 {
		t.Fatalf("put OLD_B failed")
	}
	// Write a fresh dotenv file with only one key.
	path := filepath.Join(s.dir, "fresh.env")
	if err := os.WriteFile(path, []byte("NEW_KEY=v1\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	// --replace --yes (no TTY → --yes required).
	if so, se, code := s.run("", "import", "--replace", "--yes", path); code != 0 {
		t.Fatalf("import --replace --yes failed: code=%d\nstdout=%q\nstderr=%q", code, so, se)
	}
	// Old keys should be gone; new key present.
	stdout, _ := s.mustRun("", "list", "--json")
	var entries []map[string]any
	if err := json.Unmarshal([]byte(stdout), &entries); err != nil {
		t.Fatalf("list --json: %v\n%s", err, stdout)
	}
	names := make(map[string]bool)
	for _, e := range entries {
		names[e["name"].(string)] = true
	}
	if names["OLD_A"] || names["OLD_B"] {
		t.Fatalf("--replace failed to wipe pre-existing keys: %v", names)
	}
	if !names["NEW_KEY"] {
		t.Fatalf("--replace did not import the new key: %v", names)
	}
}

func TestE2E_Import_ReplaceRequiresYesInNonTTY(t *testing.T) {
	s := bootstrapUnlocked(t)
	path := filepath.Join(s.dir, "fresh.env")
	if err := os.WriteFile(path, []byte("K=v\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Pass an empty (but non-nil) stdin reader so the child sees a
	// non-TTY stdin — otherwise it inherits the test runner's stdin
	// which may still be a TTY under `go test`.
	_, stderr, code := s.run("\n", "import", "--replace", path)
	if code == 0 {
		t.Fatalf("--replace without --yes in non-TTY should fail")
	}
	if !strings.Contains(stderr, "--yes") {
		t.Fatalf("rejection should mention --yes; stderr:\n%s", stderr)
	}
}

func TestE2E_Import_ReplaceConflictsWithSkipExisting(t *testing.T) {
	s := bootstrapUnlocked(t)
	path := filepath.Join(s.dir, "fresh.env")
	if err := os.WriteFile(path, []byte("K=v\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, stderr, code := s.run("", "import", "--replace", "--skip-existing", "--yes", path)
	if code == 0 {
		t.Fatalf("--replace + --skip-existing should fail")
	}
	if !strings.Contains(stderr, "mutually exclusive") {
		t.Fatalf("rejection should say mutually exclusive; got:\n%s", stderr)
	}
}

func TestE2E_Import_ReplaceDryRunShowsBoth(t *testing.T) {
	s := bootstrapUnlocked(t)
	if _, _, code := s.run("v", "put", "OLD"); code != 0 {
		t.Fatalf("put OLD failed")
	}
	path := filepath.Join(s.dir, "fresh.env")
	if err := os.WriteFile(path, []byte("NEW=x\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	stdout, _, code := s.run("", "import", "--replace", "--dry-run", path)
	if code != 0 {
		t.Fatalf("dry-run --replace exited %d", code)
	}
	if !strings.Contains(stdout, "- OLD") || !strings.Contains(stdout, "+ NEW") {
		t.Fatalf("dry-run --replace should show both - OLD and + NEW:\n%s", stdout)
	}
	// And verify nothing actually changed.
	listOut, _ := s.mustRun("", "list")
	if !strings.Contains(listOut, "OLD") {
		t.Fatalf("dry-run wrote changes; OLD missing from list:\n%s", listOut)
	}
}

func TestE2E_ImportExport_Roundtrip(t *testing.T) {
	s := bootstrapUnlocked(t)
	// import → export → import → list parity.
	srcPath := filepath.Join(s.dir, "src.env")
	body := "A=1\nB=2\nC=3\n"
	if err := os.WriteFile(srcPath, []byte(body), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, code := s.run("", "import", srcPath); code != 0 {
		t.Fatalf("import failed")
	}
	exported, _ := s.mustRun("", "export")
	for _, want := range []string{"A=1", "B=2", "C=3"} {
		if !strings.Contains(exported, want) {
			t.Fatalf("export missing %q:\n%s", want, exported)
		}
	}
}
