//go:build integration

// studio_test.go: end-to-end integration tests for the portal .byn studio
// daemon operations: byn.validate, byn.simulate, byn.read, byn.write (Content
// field), and config.get.
//
// All tests drive the REAL daemon via raw IPC (ipc.Client) after starting it
// with the CLI bootstrap helpers. The exec e2e pairs prove that a studio-
// authored .byn actually gates exec as the simulator predicted.
package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

const studioPW = "correct-horse-battery-staple"

// ipcClient returns an IPC client connected to the session's daemon socket.
func ipcClient(s *session) *ipc.Client {
	sockPath := filepath.Join(s.dir, "daemon.sock")
	c := ipc.NewClient(sockPath)
	c.Timeout = 30 * time.Second
	return c
}

// bootstrapStudio starts a daemon, inits and unlocks the default vault, and
// returns the session plus a ready IPC client.
func bootstrapStudio(t *testing.T) (*session, *ipc.Client) {
	t.Helper()
	s := bootstrapUnlocked(t) // uses studioPW == "correct-horse-battery-staple"
	return s, ipcClient(s)
}

// ─────────────────────────────────────────────────────────────────────────────
// byn.validate — validate .byn content without trusting
// ─────────────────────────────────────────────────────────────────────────────

// TestStudio_Validate_ValidContent confirms that well-formed .byn content
// produces zero errors and reaches the daemon.
func TestStudio_Validate_ValidContent(t *testing.T) {
	_, c := bootstrapStudio(t)

	content := "[scope]\nvault = \"default\"\n\n[exec]\nenv = [\"API_KEY\"]\nactions = [\"aws s3 ls\"]\n"
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: []byte(content)}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if len(resp.Errors) != 0 {
		t.Fatalf("expected no errors for valid content; got: %v", resp.Errors)
	}
}

// TestStudio_Validate_InvalidTOML confirms that bad TOML returns an error in
// the "toml" section (not a daemon-level failure).
func TestStudio_Validate_InvalidTOML(t *testing.T) {
	_, c := bootstrapStudio(t)

	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: []byte("not valid toml [[[")}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if len(resp.Errors) == 0 {
		t.Fatal("expected TOML error; got none")
	}
	if resp.Errors[0].Section != "toml" {
		t.Fatalf("section = %q, want \"toml\"", resp.Errors[0].Section)
	}
}

// TestStudio_Validate_WildcardWarning confirms that env="*" produces a
// warning (the result surface used by the studio's inline hints).
func TestStudio_Validate_WildcardWarning(t *testing.T) {
	_, c := bootstrapStudio(t)

	content := "[exec]\nenv = \"*\"\n"
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: []byte(content)}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if len(resp.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", resp.Errors)
	}
	found := false
	for _, w := range resp.Warnings {
		if w.Section == "exec" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected exec-section warning for wildcard env; got: %v", resp.Warnings)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// byn.simulate — simulate exec verdict
// ─────────────────────────────────────────────────────────────────────────────

// TestStudio_Simulate_Free drives simulate for a command that exactly matches
// a pinned action and verifies the verdict is "free".
func TestStudio_Simulate_Free(t *testing.T) {
	_, c := bootstrapStudio(t)

	content := "[exec]\nactions = [\"aws s3 ls\"]\n"
	var resp ipc.BynSimulateResp
	if err := c.Call(ipc.OpBynSimulate, ipc.BynSimulateReq{
		Content:     []byte(content),
		CommandLine: "aws s3 ls",
	}, &resp); err != nil {
		t.Fatalf("byn.simulate: %v", err)
	}
	if resp.Verdict != "free" {
		t.Fatalf("verdict = %q, want \"free\"", resp.Verdict)
	}
	if resp.MatchedKind != "action" {
		t.Fatalf("matched_kind = %q, want \"action\"", resp.MatchedKind)
	}
}

// TestStudio_Simulate_Auth drives simulate for a command not in the actions
// list and verifies the verdict is "auth".
func TestStudio_Simulate_Auth(t *testing.T) {
	_, c := bootstrapStudio(t)

	content := "[exec]\nactions = [\"aws s3 ls\"]\n"
	var resp ipc.BynSimulateResp
	if err := c.Call(ipc.OpBynSimulate, ipc.BynSimulateReq{
		Content:     []byte(content),
		CommandLine: "kubectl delete pod foo",
	}, &resp); err != nil {
		t.Fatalf("byn.simulate: %v", err)
	}
	if resp.Verdict != "auth" {
		t.Fatalf("verdict = %q, want \"auth\"", resp.Verdict)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// byn.read — read a .byn file with trust status
// ─────────────────────────────────────────────────────────────────────────────

// TestStudio_Read_Untrusted writes a .byn, reads it before trusting, and
// confirms the trust_status is "untrusted".
func TestStudio_Read_Untrusted(t *testing.T) {
	s, c := bootstrapStudio(t)

	projDir := filepath.Join(s.dir, "studio-read-proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dotPath := filepath.Join(projDir, ".byn")
	content := "[scope]\nvault = \"default\"\n"
	if err := os.WriteFile(dotPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var resp ipc.BynReadResp
	if err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: dotPath}, &resp); err != nil {
		t.Fatalf("byn.read: %v", err)
	}
	if resp.TrustStatus != string(trust.VerifyUntrusted) {
		t.Fatalf("trust_status = %q, want %q", resp.TrustStatus, trust.VerifyUntrusted)
	}
	if !strings.Contains(string(resp.Content), "[scope]") {
		t.Fatalf("content does not contain [scope]; got: %q", resp.Content)
	}
}

// TestStudio_Read_Trusted writes, trusts (via CLI), then reads a .byn and
// confirms the trust_status is "trusted".
func TestStudio_Read_Trusted(t *testing.T) {
	s, c := bootstrapStudio(t)

	projDir := filepath.Join(s.dir, "studio-trust-proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dotPath := filepath.Join(projDir, ".byn")
	content := "[scope]\nvault = \"default\"\n"
	if err := os.WriteFile(dotPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	// Trust via CLI.
	if _, se, code := s.runInDir(projDir, studioPW+"\n", nil, "trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("byn trust: code=%d stderr=%q", code, se)
	}

	var resp ipc.BynReadResp
	if err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: dotPath}, &resp); err != nil {
		t.Fatalf("byn.read after trust: %v", err)
	}
	if resp.TrustStatus != string(trust.VerifyTrusted) {
		t.Fatalf("trust_status = %q, want %q", resp.TrustStatus, trust.VerifyTrusted)
	}
}

// TestStudio_Read_NonBynPathRejected confirms that byn.read refuses a path
// whose basename is not ".byn" (arbitrary-file-read guard).
func TestStudio_Read_NonBynPathRejected(t *testing.T) {
	s, c := bootstrapStudio(t)

	// Write a secrets.txt that must never be readable via this endpoint.
	secretFile := filepath.Join(s.dir, "secrets.txt")
	if err := os.WriteFile(secretFile, []byte("SENSITIVE"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: secretFile}, &ipc.BynReadResp{})
	if err == nil {
		t.Fatal("expected error for non-.byn path; got none")
	}
	if !strings.Contains(err.Error(), string(ipc.CodeBadRequest)) {
		t.Fatalf("expected bad_request; got: %v", err)
	}
}

// TestStudio_Read_SymlinkBynToArbitraryFile confirms the symlink-bypass is
// blocked: a symlink named ".byn" pointing at a non-.byn file must be refused.
func TestStudio_Read_SymlinkBynToArbitraryFile(t *testing.T) {
	s, c := bootstrapStudio(t)

	// Create the "secret" file with a non-.byn name.
	secretFile := filepath.Join(s.dir, "ssh_id_rsa")
	if err := os.WriteFile(secretFile, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create a symlink named ".byn" pointing at the secret file.
	symlinkDir := filepath.Join(s.dir, "evil-project")
	if err := os.MkdirAll(symlinkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(symlinkDir, ".byn")
	if err := os.Symlink(secretFile, symlinkPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: symlinkPath}, &ipc.BynReadResp{})
	if err == nil {
		t.Fatal("symlink-named-.byn-to-non-.byn should be refused; got success")
	}
	if !strings.Contains(err.Error(), string(ipc.CodeBadRequest)) {
		t.Fatalf("expected bad_request code; got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// byn.write with Content field
// ─────────────────────────────────────────────────────────────────────────────

// TestStudio_WriteContent_VerbatimAndTrust writes a .byn via the Content
// field, trusts it in one step, then reads it back via byn.read to confirm
// both the content and trust status are correct.
func TestStudio_WriteContent_VerbatimAndTrust(t *testing.T) {
	s, c := bootstrapStudio(t)

	projDir := filepath.Join(s.dir, "studio-write-proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}

	content := "[scope]\nvault = \"default\"\n\n[exec]\nenv = [\"DB_URL\"]\nactions = [\"aws s3 ls\"]\n"
	var writeResp ipc.BynWriteResp
	if err := c.Call(ipc.OpBynWrite, ipc.BynWriteReq{
		Dir:      projDir,
		Content:  []byte(content),
		Trust:    true,
		Password: []byte(studioPW),
	}, &writeResp); err != nil {
		t.Fatalf("byn.write: %v", err)
	}
	if !writeResp.Trusted {
		t.Fatal("expected Trusted=true after write+trust")
	}

	// Read back — trust_status must be "trusted" with matching content.
	var readResp ipc.BynReadResp
	if err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: writeResp.Path}, &readResp); err != nil {
		t.Fatalf("byn.read after write: %v", err)
	}
	if readResp.TrustStatus != string(trust.VerifyTrusted) {
		t.Fatalf("trust_status = %q, want %q", readResp.TrustStatus, trust.VerifyTrusted)
	}
	if string(readResp.Content) != content {
		t.Fatalf("content mismatch; want %q, got %q", content, readResp.Content)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// config.get — read the daemon config
// ─────────────────────────────────────────────────────────────────────────────

// TestStudio_ConfigGet_ReturnsPath confirms that config.get always returns a
// non-empty path (even when the file is absent) and carries no secrets.
func TestStudio_ConfigGet_ReturnsPath(t *testing.T) {
	_, c := bootstrapStudio(t)

	var resp ipc.ConfigGetResp
	if err := c.Call(ipc.OpConfigGet, ipc.ConfigGetReq{}, &resp); err != nil {
		t.Fatalf("config.get: %v", err)
	}
	if resp.Path == "" {
		t.Fatal("config.get returned empty path")
	}
	if !filepath.IsAbs(resp.Path) {
		t.Fatalf("config path is not absolute: %q", resp.Path)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Studio-authored .byn exec e2e — prove the simulator's prediction matches
// real enforcement, for both FREE and AUTH cases.
// ─────────────────────────────────────────────────────────────────────────────

// TestStudio_ExecE2E_FreeCase: the studio authors a .byn with a pinned action,
// the simulator predicts "free", and the real exec.fetch succeeds without a
// password.
func TestStudio_ExecE2E_FreeCase(t *testing.T) {
	s, c := bootstrapStudio(t)

	projDir := filepath.Join(s.dir, "studio-exec-free")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Studio-author a .byn: DB_URL injected, "/bin/echo {{args}}" pinned free
	// (tail wildcard so any number of arguments is allowed).
	content := "[scope]\nvault = \"default\"\n\n[exec]\nenv = [\"DB_URL\"]\nactions = [\"/bin/echo {{args}}\"]\n"
	var writeResp ipc.BynWriteResp
	if err := c.Call(ipc.OpBynWrite, ipc.BynWriteReq{
		Dir:      projDir,
		Content:  []byte(content),
		Trust:    true,
		Password: []byte(studioPW),
	}, &writeResp); err != nil {
		t.Fatalf("byn.write+trust: %v", err)
	}

	// Simulator says "free" for "/bin/echo hello" (matches /bin/echo {{args}}).
	var simResp ipc.BynSimulateResp
	if err := c.Call(ipc.OpBynSimulate, ipc.BynSimulateReq{
		Content:     []byte(content),
		CommandLine: "/bin/echo hello",
	}, &simResp); err != nil {
		t.Fatalf("byn.simulate: %v", err)
	}
	if simResp.Verdict != "free" {
		t.Fatalf("simulator verdict = %q, want \"free\"", simResp.Verdict)
	}

	// Exec e2e: store DB_URL, then byn exec should succeed (free, no password).
	if _, se, code := s.run("s3cret-db", "put", "DB_URL"); code != 0 {
		t.Fatalf("put DB_URL: code=%d stderr=%q", code, se)
	}

	// Use `byn exec -- /bin/echo hello` (direct form, "--" separates the argv).
	stdout, se, code := s.runInDir(projDir, "", nil, "exec", "--", "/bin/echo", "hello")
	if code != 0 {
		t.Fatalf("exec free case: code=%d stderr=%q stdout=%q", code, se, stdout)
	}
	if !strings.Contains(stdout, "hello") {
		t.Fatalf("exec output missing 'hello': %q", stdout)
	}
}

// TestStudio_ExecE2E_AuthCase: the studio authors a .byn with NO pinned
// actions, the simulator predicts "auth", and the real exec.fetch (run
// non-interactively without a password) is refused with auth_required.
func TestStudio_ExecE2E_AuthCase(t *testing.T) {
	s, c := bootstrapStudio(t)

	projDir := filepath.Join(s.dir, "studio-exec-auth")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Studio-author a .byn: no [exec] actions → every exec requires auth.
	content := "[scope]\nvault = \"default\"\n\n[exec]\nenv = [\"DB_URL\"]\n"
	var writeResp ipc.BynWriteResp
	if err := c.Call(ipc.OpBynWrite, ipc.BynWriteReq{
		Dir:      projDir,
		Content:  []byte(content),
		Trust:    true,
		Password: []byte(studioPW),
	}, &writeResp); err != nil {
		t.Fatalf("byn.write+trust: %v", err)
	}

	// Simulator says "auth" for any command (no actions pinned).
	var simResp ipc.BynSimulateResp
	if err := c.Call(ipc.OpBynSimulate, ipc.BynSimulateReq{
		Content:     []byte(content),
		CommandLine: "/bin/echo hello",
	}, &simResp); err != nil {
		t.Fatalf("byn.simulate: %v", err)
	}
	if simResp.Verdict != "auth" {
		t.Fatalf("simulator verdict = %q, want \"auth\" (no pinned actions)", simResp.Verdict)
	}

	// Exec e2e: store DB_URL, then byn exec without a password must fail (non-TTY).
	if _, se, code := s.run("s3cret-db", "put", "DB_URL"); code != 0 {
		t.Fatalf("put DB_URL: code=%d stderr=%q", code, se)
	}

	// Use direct form with "--" separator.
	_, se, code := s.runInDir(projDir, "", nil, "exec", "--", "/bin/echo", "hello")
	if code == 0 {
		t.Fatalf("exec auth case: expected non-zero exit (auth required); got code=0 stderr=%q", se)
	}
	// The error message should indicate authorization is required.
	if !strings.Contains(se, "auth") && !strings.Contains(se, "password") && !strings.Contains(se, "authorize") {
		t.Fatalf("exec auth stderr does not mention auth/password: %q", se)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// config.set with per_action_auth is rejected as unknown key
// ─────────────────────────────────────────────────────────────────────────────

// TestStudio_ConfigSet_FlipsPerActionAuth confirms that config.set with
// per_action_auth = true in the content is rejected (strict TOML parser:
// per_action_auth is an unknown key now that the field has been removed).
func TestStudio_ConfigSet_FlipsPerActionAuth(t *testing.T) {
	_, c := bootstrapStudio(t)

	// Attempt to set config with per_action_auth — must fail with a validation error.
	newContent := "[security]\nper_action_auth = true\n"
	var setResp ipc.ConfigSetResp
	setErr := c.Call(ipc.OpConfigSet, ipc.ConfigSetReq{
		Content:  []byte(newContent),
		Password: []byte(studioPW),
	}, &setResp)
	if setErr == nil {
		t.Fatal("config.set with per_action_auth = true: expected error (unknown key), got nil")
	}
	// The strict TOML parser says "strict mode: fields in the document are
	// missing in the target struct" — it does not embed the field name.
	if !strings.Contains(setErr.Error(), "strict mode") && !strings.Contains(setErr.Error(), "unknown") {
		t.Fatalf("error %q does not indicate a strict/unknown-key parse failure", setErr.Error())
	}
}
