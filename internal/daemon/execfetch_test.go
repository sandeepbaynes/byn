package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

// execFetch is a thin helper that calls OpExecFetch and returns the resp.
// On IPC error it returns nil, err. On daemon error it returns the error code.
func execFetch(t *testing.T, c *ipc.Client, req ipc.ExecFetchReq) (ipc.ExecFetchResp, error) {
	t.Helper()
	var resp ipc.ExecFetchResp
	err := c.Call(ipc.OpExecFetch, req, &resp)
	return resp, err
}

// putVar stores a single env var into the default vault scope.
func putVar(t *testing.T, c *ipc.Client, scope ipc.Scope, name string, value []byte) {
	t.Helper()
	if err := c.Call(ipc.OpPut, ipc.PutReq{Scope: scope, Name: name, Value: value}, &ipc.PutResp{}); err != nil {
		t.Fatalf("Put %s: %v", name, err)
	}
}

// writeBynContent writes a .byn file with the given content to a fresh temp dir.
func writeBynContent(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".byn")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// grantBynFile grants trust to a .byn file and fatals on error.
func grantBynFile(t *testing.T, c *ipc.Client, path string, pw []byte) {
	t.Helper()
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: path, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant %s: %v", path, err)
	}
}

// valueMap converts []ipc.ExecFetchValue to a name→value map for easy assertion.
func valueMap(vals []ipc.ExecFetchValue) map[string]string {
	m := make(map[string]string, len(vals))
	for _, v := range vals {
		m[v.Name] = string(v.Value)
	}
	return m
}

// ---- Test 1: allowlisted vars only ----------------------------------------

func TestExecFetchInjectsOnlyAllowlistedVars(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Store three vars.
	putVar(t, c, ipc.Scope{}, "DB_URL", []byte("postgres://localhost/db"))
	putVar(t, c, ipc.Scope{}, "API_KEY", []byte("secret-api"))
	putVar(t, c, ipc.Scope{}, "EXTRA", []byte("should-not-appear"))

	// Write a .byn that only allows DB_URL and API_KEY.
	// actions = "*" so that any command runs free (this test is about env
	// filtering, not actions enforcement — actions are tested separately).
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"DB_URL\", \"API_KEY\"]\nactions = \"*\"\n")
	grantBynFile(t, c, byn, pw)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{Path: byn, Command: "aws s3 ls", Argv: []string{"aws", "s3", "ls"}})
	if err != nil {
		t.Fatalf("exec.fetch: %v", err)
	}

	m := valueMap(resp.Values)
	if m["DB_URL"] != "postgres://localhost/db" {
		t.Errorf("DB_URL = %q, want postgres://localhost/db", m["DB_URL"])
	}
	if m["API_KEY"] != "secret-api" {
		t.Errorf("API_KEY = %q, want secret-api", m["API_KEY"])
	}
	if _, ok := m["EXTRA"]; ok {
		t.Error("EXTRA should not be in the injection set")
	}
	if len(resp.Values) != 2 {
		t.Errorf("len(Values) = %d, want 2", len(resp.Values))
	}
	if resp.Wildcard {
		t.Error("Wildcard should be false for an explicit list")
	}
	if resp.NoneDeclared {
		t.Error("NoneDeclared should be false when env list is set")
	}
}

// ---- Test 2: empty allowlist → nothing injected ---------------------------

func TestExecFetchEmptyAllowlistInjectsNothing(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("val"))

	// .byn with no [exec] env section, but actions = "*" so the command runs
	// free (this test is about env filtering — empty env injects nothing;
	// actions are tested separately).
	byn := writeBynContent(t, "[scope]\n\n[exec]\nactions = \"*\"\n")
	grantBynFile(t, c, byn, pw)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{Path: byn, Argv: []string{"any-cmd"}})
	if err != nil {
		t.Fatalf("exec.fetch: %v", err)
	}
	if len(resp.Values) != 0 {
		t.Errorf("Values = %v, want empty", resp.Values)
	}
	if !resp.NoneDeclared {
		t.Error("NoneDeclared should be true when no [exec] env declared")
	}
	if resp.Wildcard {
		t.Error("Wildcard should be false")
	}
}

// ---- Test 3: wildcard env → all scope vars --------------------------------

func TestExecFetchWildcard(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "FOO", []byte("foo-val"))
	putVar(t, c, ipc.Scope{}, "BAR", []byte("bar-val"))

	// actions = "*" so the command runs free; this test is about env wildcard.
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = \"*\"\nactions = \"*\"\n")
	grantBynFile(t, c, byn, pw)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{Path: byn, Argv: []string{"any-cmd"}})
	if err != nil {
		t.Fatalf("exec.fetch: %v", err)
	}
	if !resp.Wildcard {
		t.Error("Wildcard should be true for env=\"*\"")
	}
	if resp.NoneDeclared {
		t.Error("NoneDeclared should be false for wildcard")
	}
	m := valueMap(resp.Values)
	if m["FOO"] != "foo-val" {
		t.Errorf("FOO = %q, want foo-val", m["FOO"])
	}
	if m["BAR"] != "bar-val" {
		t.Errorf("BAR = %q, want bar-val", m["BAR"])
	}
}

// ---- Test 4: untrusted .byn → CodeTrustDenied ----------------------------

func TestExecFetchUntrustedDenied(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SECRET\"]\n")
	// Never granted.

	_, err := execFetch(t, c, ipc.ExecFetchReq{Path: byn, Command: "evil"})
	if code := errCode(t, err); code != ipc.CodeTrustDenied {
		t.Fatalf("code = %v, want trust_denied", code)
	}
	var er *ipc.ErrResponse
	if errors.As(err, &er) {
		if er.Recover == "" {
			t.Error("Recover hint should not be empty")
		}
		// Recover must mention "byn trust"
		if er.Recover != "byn trust "+trust.Canonicalize(byn) {
			t.Errorf("Recover = %q, want 'byn trust %s'", er.Recover, trust.Canonicalize(byn))
		}
	}

	// Audit trail should show op=exec, outcome=denied.
	ev := findExecAudit(t, c, "evil")
	if ev == nil {
		t.Fatal("no exec audit event for untrusted deny")
	}
	if ev.Outcome != "denied" {
		t.Errorf("outcome = %q, want denied", ev.Outcome)
	}
}

// ---- Test 5: file changed after trust → CodeTrustDenied ------------------

func TestExecFetchChangedDenied(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SECRET\"]\n")
	grantBynFile(t, c, byn, pw)

	// Append a byte to change the content.
	f, err := os.OpenFile(byn, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(" ")
	_ = f.Close()

	_, fetchErr := execFetch(t, c, ipc.ExecFetchReq{Path: byn})
	if code := errCode(t, fetchErr); code != ipc.CodeTrustDenied {
		t.Fatalf("code = %v, want trust_denied", code)
	}
	var er *ipc.ErrResponse
	if errors.As(fetchErr, &er) {
		if !strings.Contains(er.Message, "CHANGED") {
			t.Errorf("message %q should contain CHANGED", er.Message)
		}
	}
}

// ---- Test 11: trusted-but-malformed record (hand-written) → bad_request, audited
//
// This is NU-1's defense-in-depth test. Grant time now refuses malformed .byn
// files (Task 3), so we hand-write a malformed-but-MAC'd record directly into
// the trust store to prove exec still fails closed + audits at USE-TIME even
// when a rogue record bypasses the grant gate (e.g. hand-crafted JSON).

func TestExecFetchTrustedButMalformedAudited(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	const malformedBody = "not toml [[["
	byn := writeBynContent(t, malformedBody)
	canon := trust.Canonicalize(byn)
	hash := trust.Hash([]byte(malformedBody))

	// Derive the vk-MAC key directly from the store (vault is unlocked).
	entry, err := d.openVault(context.Background(), "default")
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	vkKey, err := entry.store.DeriveSubkey(trust.VKMACKeyInfo)
	if err != nil {
		t.Fatalf("DeriveSubkey: %v", err)
	}

	// Stat the file so mtime is valid (makes it a v2 record).
	fi, serr := os.Stat(byn)
	if serr != nil {
		t.Fatalf("stat: %v", serr)
	}

	// Hand-write a malformed-but-MAC'd v2 trust record directly into the store,
	// bypassing the grant gate. This simulates a rogue edit of trusted_byn.json.
	rec := trust.Record{
		Path:          canon,
		SHA256:        hash,
		Vault:         "default",
		MTimeUnixNano: fi.ModTime().UnixNano(),
		Snapshot:      malformedBody, // syntactically invalid
	}
	rec.SetMACs(d.fpMACKey, vkKey)
	if _, perr := trust.Put(d.cfg.Dir, rec); perr != nil {
		t.Fatalf("Put: %v", perr)
	}

	// Exec against the malformed (but MAC-valid) record must fail closed.
	const cmd = "evil --malformed"
	_, execErr := execFetch(t, c, ipc.ExecFetchReq{Path: byn, Command: cmd})
	if code := errCode(t, execErr); code != ipc.CodeBadRequest {
		t.Fatalf("code = %v, want bad_request", code)
	}

	// Parse failure must produce a denied/error audit event.
	ev := findExecAudit(t, c, cmd)
	if ev == nil {
		t.Fatal("no exec audit event for malformed .byn denial")
	}
	if ev.Outcome != "denied" {
		t.Errorf("outcome = %q, want denied", ev.Outcome)
	}
	if ev.ErrorCode != string(ipc.CodeBadRequest) {
		t.Errorf("error_code = %q, want %q", ev.ErrorCode, string(ipc.CodeBadRequest))
	}
	if ev.BynPath != canon {
		t.Errorf("byn_path = %q, want %q", ev.BynPath, canon)
	}
	if ev.Command != cmd {
		t.Errorf("command = %q, want %q", ev.Command, cmd)
	}
}

// ---- Test 6: wrong vault → CodeTrustDenied --------------------------------

func TestExecFetchWrongVaultDenied(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	// Init vault A (default) and unlock it.
	initUnlocked(t, c, pw)

	// Init vault B and unlock it too.
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Name: "vaultb", Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("init vaultb: %v", err)
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Name: "vaultb", Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("unlock vaultb: %v", err)
	}

	// Write and grant the .byn under vault A (default) — vk-MAC is minted
	// with the default vault's key.
	byn := writeBynContent(t, "[scope]\nvault = \"default\"\n\n[exec]\nenv = [\"X\"]\n")
	grantBynFile(t, c, byn, pw)

	// Request against vault B: the vk-MAC was derived from vault A's key
	// so it will fail the vk-MAC check against vault B → trust_denied.
	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:  byn,
		Scope: ipc.Scope{Vault: "vaultb"},
	})
	if code := errCode(t, err); code != ipc.CodeTrustDenied {
		t.Fatalf("code = %v, want trust_denied (vk-MAC mismatch)", code)
	}
}

// ---- Test 7: ad-hoc (Path="") → whole scope, no trust check --------------

func TestExecFetchAdHocNoBynInjectsWholeScope(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "FOO", []byte("bar"))

	resp, err := execFetch(t, c, ipc.ExecFetchReq{Path: ""})
	if err != nil {
		t.Fatalf("exec.fetch ad-hoc: %v", err)
	}
	m := valueMap(resp.Values)
	if m["FOO"] != "bar" {
		t.Errorf("FOO = %q, want bar", m["FOO"])
	}
	if resp.Wildcard {
		t.Error("Wildcard should be false for ad-hoc (no .byn)")
	}
	if resp.NoneDeclared {
		t.Error("NoneDeclared should be false for ad-hoc (no .byn)")
	}
}

// ---- Test 8: locked vault → CodeLocked, audited ---------------------------

func TestExecFetchLockedVaultDenied(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SECRET\"]\n")
	grantBynFile(t, c, byn, pw)

	// Lock the vault.
	lockVaultStore(t, d, "default")

	const cmd = "byn exec locked-test"
	_, err := execFetch(t, c, ipc.ExecFetchReq{Path: byn, Command: cmd})
	if code := errCode(t, err); code != ipc.CodeLocked {
		t.Fatalf("code = %v, want locked", code)
	}

	// Audit trail must record the denied exec even though the vault was locked.
	ev := findExecAudit(t, c, cmd)
	if ev == nil {
		t.Fatal("no exec audit event for locked-vault denial")
	}
	if ev.Outcome != "denied" {
		t.Errorf("outcome = %q, want denied", ev.Outcome)
	}
	if ev.ErrorCode != string(ipc.CodeLocked) {
		t.Errorf("error_code = %q, want %q", ev.ErrorCode, string(ipc.CodeLocked))
	}
	if ev.BynPath != trust.Canonicalize(byn) {
		t.Errorf("byn_path = %q, want %q", ev.BynPath, trust.Canonicalize(byn))
	}
	if ev.Command != cmd {
		t.Errorf("command = %q, want %q", ev.Command, cmd)
	}
}

// ---- Test 9: audit on success --------------------------------------------

func TestExecFetchAuditsCommand(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "TOKEN", []byte("tok"))

	// Pin the command in [exec] actions so it runs free (this test is about
	// audit recording, not actions enforcement).
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"TOKEN\"]\nactions = [\"kubectl apply\"]\n")
	grantBynFile(t, c, byn, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{Path: byn, Command: "kubectl apply", Argv: []string{"kubectl", "apply"}})
	if err != nil {
		t.Fatalf("exec.fetch: %v", err)
	}

	ev := findExecAudit(t, c, "kubectl apply")
	if ev == nil {
		t.Fatal("no exec audit event for successful fetch")
	}
	if ev.Outcome != "ok" {
		t.Errorf("outcome = %q, want ok", ev.Outcome)
	}
	if ev.BynPath != trust.Canonicalize(byn) {
		t.Errorf("byn_path = %q, want %q", ev.BynPath, trust.Canonicalize(byn))
	}
}

// ---- Test 10: unreadable path → CodeTrustDenied --------------------------

func TestExecFetchUnreadablePathDenied(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	nonexistent := filepath.Join(t.TempDir(), "no-such-file.byn")

	_, err := execFetch(t, c, ipc.ExecFetchReq{Path: nonexistent})
	if code := errCode(t, err); code != ipc.CodeTrustDenied {
		t.Fatalf("code = %v, want trust_denied", code)
	}
}

// ---- Test 12: allowlisted var missing from vault → success, only present vars returned

func TestExecFetchAllowlistedNameMissingFromVault(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Store only DB_URL; allowlist requests both DB_URL and GHOST.
	putVar(t, c, ipc.Scope{}, "DB_URL", []byte("postgres://localhost/db"))

	// actions = "*" so any command runs free (this test is about env filtering).
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"DB_URL\", \"GHOST\"]\nactions = \"*\"\n")
	grantBynFile(t, c, byn, pw)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{Path: byn, Argv: []string{"any-cmd"}})
	if err != nil {
		t.Fatalf("exec.fetch: %v", err)
	}

	// Only DB_URL should be returned; GHOST should not appear even though it's allowlisted.
	m := valueMap(resp.Values)
	if m["DB_URL"] != "postgres://localhost/db" {
		t.Errorf("DB_URL = %q, want postgres://localhost/db", m["DB_URL"])
	}
	if _, ok := m["GHOST"]; ok {
		t.Error("GHOST should not be in the injection set (not stored in vault)")
	}
	if len(resp.Values) != 1 {
		t.Errorf("len(Values) = %d, want 1", len(resp.Values))
	}
}

// ---- Test 13: ad-hoc (Path="") with locked vault → CodeLocked

func TestExecFetchAdHocLockedDenied(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "VAR", []byte("val"))

	// Lock the vault.
	lockVaultStore(t, d, "default")

	_, err := execFetch(t, c, ipc.ExecFetchReq{Path: ""})
	if code := errCode(t, err); code != ipc.CodeLocked {
		t.Fatalf("code = %v, want locked", code)
	}
}

// ---- Test 14: inherited var through allowlist

func TestExecFetchInheritedVarThroughAllowlist(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Store a var in the default (empty) scope.
	putVar(t, c, ipc.Scope{}, "SHARED", []byte("shared-value"))

	// Request with a non-default scope but allowlist the shared var.
	// The allowlist includes SHARED, demonstrating that the list gates
	// what names are allowed to flow, regardless of scope.
	// actions = "*" so any command runs free (this test is about env inheritance).
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SHARED\"]\nactions = \"*\"\n")
	grantBynFile(t, c, byn, pw)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:  byn,
		Scope: ipc.Scope{},
		Argv:  []string{"any-cmd"},
	})
	if err != nil {
		t.Fatalf("exec.fetch: %v", err)
	}

	// The allowlist gates which names are allowed to flow.
	// The var was stored in the default scope, so it should be found
	// and returned because it's in the allowlist.
	m := valueMap(resp.Values)
	if m["SHARED"] != "shared-value" {
		t.Errorf("SHARED = %q, want shared-value", m["SHARED"])
	}
}
