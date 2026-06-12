package daemon

// Tests for [security] per_action_auth gate on get / overwrite-put / delete.
// Trusted-.byn exec.fetch is credential-free; ad-hoc exec (Path="") is
// gated. Insert (new name) and list stay free per the agent-autonomy matrix.

import (
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// startPerActionDaemonWithClient starts a daemon and returns both the daemon
// and a connected client. Under the NU-3 authorization matrix the per-action
// auth gate is always active (session-or-credentials required for value-
// touching ops); there is no separate flag to enable.
func startPerActionDaemonWithClient(t *testing.T) (*Daemon, *ipc.Client) {
	t.Helper()
	dir := shortTempDir(t)
	d := startBareDaemon(t, Config{Dir: dir})
	return d, ipc.NewClient(d.SocketPath())
}

// ---- get gate ----------------------------------------------------------

// TestPerActionGetWithoutPasswordAuthRequired: unlocked vault, flag on →
// get requires auth.
func TestPerActionGetWithoutPasswordAuthRequired(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("val")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	// Get without password/token → auth_required.
	c.Session = nil
	err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY"}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("code = %v, want auth_required", code)
	}

	// Vault must stay unlocked — auth_required does not lock.
	if d.lookupVault("default").store.IsLocked() {
		t.Error("vault should stay unlocked after auth_required on get")
	}

	// Audit trail should record a denied event.
	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 20}, &tail); err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	found := false
	for _, ev := range tail.Events {
		if ev.Op == "get" && ev.Outcome == "denied" && ev.ErrorCode == string(ipc.CodeAuthRequired) {
			found = true
		}
	}
	if !found {
		t.Error("expected a denied get audit event with error_code auth_required")
	}
}

// TestPerActionGetWithPasswordSucceeds: correct password → value returned.
func TestPerActionGetWithPasswordSucceeds(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("secret")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	var resp ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY", Password: pw}, &resp); err != nil {
		t.Fatalf("get with password: %v", err)
	}
	if string(resp.Value) != "secret" {
		t.Errorf("value = %q, want secret", resp.Value)
	}
}

// TestPerActionGetWrongPasswordDenied: wrong password → CodeWrongPassword;
// second immediate attempt with the wrong password hits backoff (rate limited).
func TestPerActionGetWrongPasswordDenied(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	// First wrong password → wrong_password.
	c.Session = nil
	err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY", Password: []byte("nope")}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("first wrong pw: code = %v, want wrong_password", code)
	}

	// Second wrong password immediately → rate_limited (the shared limiter
	// records one failure above; a second triggers backoff).
	err = c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY", Password: []byte("nope2")}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeRateLimited {
		t.Fatalf("second wrong pw: code = %v, want rate_limited", code)
	}
	// Pin the retry-after rendering: the Recover hint must include a duration
	// in seconds (e.g. "retry after 1s").
	var rateLimitErr *ipc.ErrResponse
	if errors.As(err, &rateLimitErr) {
		if !regexp.MustCompile(`retry after \d+s`).MatchString(rateLimitErr.Recover) {
			t.Errorf("rate-limited Recover = %q, want to match `retry after \\d+s`", rateLimitErr.Recover)
		}
	}
}

// TestPerActionGetPresenceTokenSucceeds: mint a token, first use OK, second use
// rejected (single-use).
func TestPerActionGetPresenceTokenSucceeds(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("tok-val")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	tok, err := d.presenceTokens.mint("default", time.Now())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// First use → ok.
	c.Session = nil
	var resp ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY", PresenceToken: tok}, &resp); err != nil {
		t.Fatalf("get with token: %v", err)
	}
	if string(resp.Value) != "tok-val" {
		t.Errorf("value = %q, want tok-val", resp.Value)
	}

	// Second use of the same token → auth_required (already consumed).
	err = c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY", PresenceToken: tok}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("token replay: code = %v, want auth_required", code)
	}
}

// TestPerActionPresenceTokenWrongVaultRejected: presence token minted for one
// vault is rejected when used on a different vault. The token must be consumed
// (burned) even if the vault check fails, pinning the one-shot semantics with
// fail-closed behavior: a token already attempted on the wrong vault is
// immediately invalid for its own vault.
func TestPerActionPresenceTokenWrongVaultRejected(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	// Init and unlock the default vault.
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "DEFAULT_KEY", Value: []byte("default-val")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put in default: %v", err)
	}

	// Init and unlock a second vault called "other".
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Name: "other", Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("init other vault: %v", err)
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Name: "other", Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("unlock other vault: %v", err)
	}

	// Store a secret in the "other" vault.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Scope: ipc.Scope{Vault: "other"}, Name: "OTHER_KEY", Value: []byte("other-val")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put in other: %v", err)
	}

	// Mint a presence token for the "other" vault.
	tok, err := d.presenceTokens.mint("other", time.Now())
	if err != nil {
		t.Fatalf("mint for other: %v", err)
	}

	// Attempt get on "default" vault presenting the token minted for "other":
	// must be rejected with auth_required because the token's vault doesn't match.
	c.Session = nil
	err = c.Call(ipc.OpGet, ipc.GetReq{Name: "DEFAULT_KEY", PresenceToken: tok}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("cross-vault get: code = %v, want auth_required", code)
	}

	// Now attempt get on "other" vault (the token's rightful vault) with the
	// SAME token. This must ALSO fail with auth_required because the token was
	// BURNED by the previous failed attempt. This pins the consume-deletes-before-
	// vault-check semantics: the token is already consumed (and never replayable)
	// even though the previous attempt failed the vault check. This is intentional
	// fail-closed behavior — once a token is presented, it's gone forever,
	// regardless of success or failure.
	err = c.Call(ipc.OpGet, ipc.GetReq{Scope: ipc.Scope{Vault: "other"}, Name: "OTHER_KEY", PresenceToken: tok}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("token on rightful vault after burn: code = %v, want auth_required (already consumed)", code)
	}
}

// ---- put gate ----------------------------------------------------------

// TestPerActionInsertStaysFree: put a new name with no password → ok (insert
// is free per the autonomy matrix).
func TestPerActionInsertStaysFree(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// No password, brand new name.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "NEW_KEY", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("free insert: %v", err)
	}
}

// TestPerActionInsertInheritedNameStaysFree: a name exists in the default env
// only; put into a non-default env scope (creating an override) is still a
// free insert — ErrExists is row-exact (project_id+env_id+name), so a
// different env_id never blocks the insert. This pins the CreateOnly
// row-exactness guarantee.
func TestPerActionInsertInheritedNameStaysFree(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Create a project and a non-default env.
	if err := c.Call(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "svc"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Fatalf("project create: %v", err)
	}
	if err := c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "svc", Name: "staging"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatalf("env create: %v", err)
	}

	// Store a name in the default env of the project (default env_id).
	defaultScope := ipc.Scope{Project: "svc"}
	if err := c.Call(ipc.OpPut, ipc.PutReq{Scope: defaultScope, Name: "SHARED", Value: []byte("default-val")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put default: %v", err)
	}

	// Put the same name into the staging env (different env_id) without a
	// password — must succeed as a free insert (override, not an overwrite of
	// the same row).
	stagingScope := ipc.Scope{Project: "svc", Env: "staging"}
	if err := c.Call(ipc.OpPut, ipc.PutReq{Scope: stagingScope, Name: "SHARED", Value: []byte("staging-val")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("free insert into non-default env: %v", err)
	}

	// Verify the staging value is independently readable with the password.
	var resp ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Scope: stagingScope, Name: "SHARED", Password: pw}, &resp); err != nil {
		t.Fatalf("get staging: %v", err)
	}
	if string(resp.Value) != "staging-val" {
		t.Errorf("staging value = %q, want staging-val", resp.Value)
	}
}

// TestPerActionOverwriteRequiresAuth: put an existing name with no password →
// auth_required; with correct password → ok; denied attempt is audited.
func TestPerActionOverwriteRequiresAuth(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Seed the entry.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v1")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put seed: %v", err)
	}

	// Overwrite without password → auth_required.
	c.Session = nil
	err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v2")}, &ipc.PutResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("overwrite no pw: code = %v, want auth_required", code)
	}

	// Audit trail must record the denied overwrite.
	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 20}, &tail); err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	foundDenied := false
	for _, ev := range tail.Events {
		if ev.Op == "put" && ev.Outcome == "denied" && ev.ErrorCode == string(ipc.CodeAuthRequired) {
			foundDenied = true
		}
	}
	if !foundDenied {
		t.Error("expected a denied put audit event with error_code auth_required")
	}

	// Overwrite with correct password → ok.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v2"), Password: pw}, &ipc.PutResp{}); err != nil {
		t.Fatalf("overwrite with pw: %v", err)
	}

	// After a successful gated overwrite there must be EXACTLY ONE "put" audit
	// event with outcome "ok" — the failed CreateOnly probe must NOT emit a
	// second put event.
	var tail2 ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 30}, &tail2); err != nil {
		t.Fatalf("audit tail2: %v", err)
	}
	okCount := 0
	for _, ev := range tail2.Events {
		if ev.Op == "put" && ev.Outcome == "ok" {
			okCount++
		}
	}
	// seed insert (first put, free) + successful overwrite = 2 ok put events total;
	// the failed CreateOnly probe must not add a third.
	if okCount != 2 {
		t.Errorf("ok put audit events = %d, want exactly 2 (seed + overwrite, no probe duplicate)", okCount)
	}

	// Confirm the value was updated.
	var resp ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY", Password: pw}, &resp); err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(resp.Value) != "v2" {
		t.Errorf("value = %q, want v2", resp.Value)
	}
}

// TestPerActionOverwritePresenceTokenSucceeds: overwrite authorized via a
// presence token (passkey-ceremony alternative to the master password).
func TestPerActionOverwritePresenceTokenSucceeds(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Seed the entry.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v1")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put seed: %v", err)
	}

	// Mint a presence token for the default vault.
	tok, err := d.presenceTokens.mint("default", time.Now())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Overwrite using the presence token — must succeed.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v2"), PresenceToken: tok}, &ipc.PutResp{}); err != nil {
		t.Fatalf("overwrite with presence token: %v", err)
	}

	// Confirm the value was updated.
	var resp ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY", Password: pw}, &resp); err != nil {
		t.Fatalf("get after token overwrite: %v", err)
	}
	if string(resp.Value) != "v2" {
		t.Errorf("value = %q, want v2", resp.Value)
	}
}

// TestPerActionCreateOnlyConflictStillExists: CreateOnly=true on an existing
// name → CodeAlreadyExists (not auth_required). The client said "create only"
// so we must not go down the auth-then-overwrite path.
func TestPerActionCreateOnlyConflictStillExists(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Seed.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v1")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put seed: %v", err)
	}

	// CreateOnly on existing → already_exists (not auth_required).
	err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v2"), CreateOnly: true}, &ipc.PutResp{})
	if code := errCode(t, err); code != ipc.CodeAlreadyExists {
		t.Fatalf("create_only conflict: code = %v, want already_exists", code)
	}
}

// ---- delete gate -------------------------------------------------------

// TestPerActionDeleteRequiresAuthEvenUnlocked: vault unlocked, no password/token
// → auth_required (not the old "free while unlocked" behaviour); audit event recorded.
func TestPerActionDeleteRequiresAuthEvenUnlocked(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	// Vault is unlocked but flag is on — delete still needs auth.
	if d.lookupVault("default").store.IsLocked() {
		t.Fatal("precondition: vault should be unlocked")
	}
	c.Session = nil
	err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "KEY"}, &ipc.DeleteResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("code = %v, want auth_required", code)
	}

	// Audit trail must record the denied delete.
	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 20}, &tail); err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	found := false
	for _, ev := range tail.Events {
		if ev.Op == "delete" && ev.Outcome == "denied" && ev.ErrorCode == string(ipc.CodeAuthRequired) {
			found = true
		}
	}
	if !found {
		t.Error("expected a denied delete audit event with error_code auth_required")
	}
}

// TestPerActionDeleteLockedWithPasswordSucceeds: flag on + locked vault +
// correct password → delete succeeds WITHOUT unlocking the vault.
func TestPerActionDeleteLockedWithPasswordSucceeds(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	lockVaultStore(t, d, "default")

	if err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "KEY", Password: pw}, &ipc.DeleteResp{}); err != nil {
		t.Fatalf("delete locked with pw: %v", err)
	}
	// Vault must stay locked after the authorized delete.
	if !d.lookupVault("default").store.IsLocked() {
		t.Error("vault should stay locked after per-action-auth delete")
	}
}

// ---- env.clear gate -------------------------------------------------------

// TestPerActionEnvClearRequiresAuth: flag on + unlocked + no creds → auth_required;
// with password → clears entries; denied attempt is audited.
func TestPerActionEnvClearRequiresAuth(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Seed two entries.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "K1", Value: []byte("a")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put K1: %v", err)
	}
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "K2", Value: []byte("b")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put K2: %v", err)
	}

	// env.clear without creds → auth_required.
	c.Session = nil
	err := c.Call(ipc.OpEnvClear, ipc.EnvClearReq{}, &ipc.EnvClearResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("env.clear no creds: code = %v, want auth_required", code)
	}

	// Audit trail must record the denied clear.
	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 20}, &tail); err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	foundDenied := false
	for _, ev := range tail.Events {
		if ev.Op == "clear" && ev.Outcome == "denied" && ev.ErrorCode == string(ipc.CodeAuthRequired) {
			foundDenied = true
		}
	}
	if !foundDenied {
		t.Error("expected a denied clear audit event with error_code auth_required")
	}

	// env.clear with correct password → clears entries.
	var clearResp ipc.EnvClearResp
	if err := c.Call(ipc.OpEnvClear, ipc.EnvClearReq{Password: pw}, &clearResp); err != nil {
		t.Fatalf("env.clear with password: %v", err)
	}
	if clearResp.Deleted != 2 {
		t.Errorf("deleted = %d, want 2", clearResp.Deleted)
	}

	// Confirm entries are gone.
	var listResp ipc.ListResp
	if err := c.Call(ipc.OpList, ipc.ListReq{}, &listResp); err != nil {
		t.Fatalf("list after clear: %v", err)
	}
	if len(listResp.Secrets) != 0 {
		t.Errorf("secrets after clear = %d, want 0", len(listResp.Secrets))
	}
}

// TestPerActionEnvClearFlagOffUnchanged: flag off → env.clear works with no
// creds while the vault is unlocked (today's behaviour unchanged).
func TestPerActionEnvClearFlagOffUnchanged(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Seed entries.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "K1", Value: []byte("a")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	// env.clear without password → should succeed (flag off, vault unlocked).
	var clearResp ipc.EnvClearResp
	if err := c.Call(ipc.OpEnvClear, ipc.EnvClearReq{}, &clearResp); err != nil {
		t.Fatalf("env.clear no pw (flag off): %v", err)
	}
	if clearResp.Deleted != 1 {
		t.Errorf("deleted = %d, want 1", clearResp.Deleted)
	}
}

// ---- rename gate ----------------------------------------------------------

// TestPerActionRenameRequiresAuth: flag on + unlocked + no creds → auth_required;
// with password → renamed; denied attempt is audited.
func TestPerActionRenameRequiresAuth(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Seed an entry.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "OLD", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	// rename without creds → auth_required.
	c.Session = nil
	err := c.Call(ipc.OpRename, ipc.RenameReq{OldName: "OLD", NewName: "NEW"}, &ipc.RenameResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("rename no creds: code = %v, want auth_required", code)
	}

	// Audit trail must record the denied rename.
	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 20}, &tail); err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	foundDenied := false
	for _, ev := range tail.Events {
		if ev.Op == "rename" && ev.Outcome == "denied" && ev.ErrorCode == string(ipc.CodeAuthRequired) {
			foundDenied = true
		}
	}
	if !foundDenied {
		t.Error("expected a denied rename audit event with error_code auth_required")
	}

	// rename with correct password → renamed.
	if err := c.Call(ipc.OpRename, ipc.RenameReq{OldName: "OLD", NewName: "NEW", Password: pw}, &ipc.RenameResp{}); err != nil {
		t.Fatalf("rename with password: %v", err)
	}

	// Confirm the new name is readable and old name is gone.
	var listResp ipc.ListResp
	if err := c.Call(ipc.OpList, ipc.ListReq{}, &listResp); err != nil {
		t.Fatalf("list after rename: %v", err)
	}
	names := make(map[string]bool)
	for _, s := range listResp.Secrets {
		names[s.Name] = true
	}
	if !names["NEW"] {
		t.Error("NEW not found after rename")
	}
	if names["OLD"] {
		t.Error("OLD still present after rename")
	}
}

// TestPerActionRenameFlagOffUnchanged: flag off → rename works with no creds
// while the vault is unlocked (today's behaviour unchanged).
func TestPerActionRenameFlagOffUnchanged(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Seed an entry.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "OLD", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	// rename without password → should succeed (flag off, vault unlocked).
	if err := c.Call(ipc.OpRename, ipc.RenameReq{OldName: "OLD", NewName: "NEW"}, &ipc.RenameResp{}); err != nil {
		t.Fatalf("rename no pw (flag off): %v", err)
	}

	// Confirm rename happened.
	var listResp ipc.ListResp
	if err := c.Call(ipc.OpList, ipc.ListReq{}, &listResp); err != nil {
		t.Fatalf("list: %v", err)
	}
	names := make(map[string]bool)
	for _, s := range listResp.Secrets {
		names[s.Name] = true
	}
	if !names["NEW"] {
		t.Error("NEW not found after flag-off rename")
	}
	if names["OLD"] {
		t.Error("OLD still present after flag-off rename")
	}
}

// ---- exec.fetch trusted .byn is unaffected --------------------------------

// TestPerActionExecFetchUnaffected: exec.fetch returns values with NO password
// while per_action_auth is on. The trusted .byn + pinned action is the
// authorization. per_action_auth does NOT gate trusted-.byn exec — only the
// .byn's own [exec] actions contract matters.
func TestPerActionExecFetchUnaffected(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	// Pin "myapp" in [exec] actions so it runs free regardless of per_action_auth.
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SECRET\"]\nactions = [\"myapp\"]\n")
	grantBynFile(t, c, byn, pw)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{Path: byn, Command: "myapp", Argv: []string{"myapp"}})
	if err != nil {
		t.Fatalf("exec.fetch with per_action_auth on (pinned action): %v", err)
	}
	m := valueMap(resp.Values)
	if m["SECRET"] != "s3cret" {
		t.Errorf("SECRET = %q, want s3cret (pinned action must run free)", m["SECRET"])
	}
}

// ---- ad-hoc exec gate under per_action_auth --------------------------------

// TestExecFetchAdHocFlagOnDenied: flag on + Path="" + no creds → auth_required,
// audited.
func TestExecFetchAdHocFlagOnDenied(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("val"))

	_, err := execFetch(t, c, ipc.ExecFetchReq{Path: "", Command: "adhoc-cmd"})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("code = %v, want auth_required", code)
	}

	// Must carry the exec-specific recover hint.
	var em *ipc.ErrResponse
	if errors.As(err, &em) {
		if em.Recover == "" {
			t.Error("Recover hint must not be empty for ad-hoc auth_required")
		}
	}

	// Denied attempt must be audited.
	var tail ipc.AuditTailResp
	if err2 := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 30}, &tail); err2 != nil {
		t.Fatalf("audit tail: %v", err2)
	}
	found := false
	for _, ev := range tail.Events {
		if ev.Op == "exec" && ev.Outcome == "denied" && ev.ErrorCode == string(ipc.CodeAuthRequired) {
			found = true
		}
	}
	if !found {
		t.Error("expected a denied exec audit event with error_code auth_required")
	}
}

// TestExecFetchAdHocFlagOnWithPasswordSucceeds: flag on + Path="" + correct
// password → success, whole scope returned.
func TestExecFetchAdHocFlagOnWithPasswordSucceeds(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     "",
		Command:  "adhoc-cmd",
		Password: pw,
	})
	if err != nil {
		t.Fatalf("ad-hoc exec with password: %v", err)
	}
	m := valueMap(resp.Values)
	if m["SECRET"] != "s3cret" {
		t.Errorf("SECRET = %q, want s3cret", m["SECRET"])
	}
}

// Note: TestExecFetchAdHocFlagOffUnchanged and TestExecFetchAdHocNoBynInjectsWholeScope
// were deleted (NU-3 spec review). They asserted free whole-scope ad-hoc exec — semantics
// that no longer exist. The replacement tests live in execfetch_test.go:
// TestExecFetchAdHocPasswordSucceeds, TestExecFetchAdHocWrongPasswordDenied,
// TestExecFetchAdHocPresenceTokenSucceeds.

// TestExecFetchTrustedStillFreeWithFlagOn: trusted .byn exec with a pinned
// action stays credential-free even with per_action_auth on — the .byn
// contract (the .byn + the pinned action) is the authorization.
func TestExecFetchTrustedStillFreeWithFlagOn(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "KEY", []byte("value"))

	// Pin "myapp" in [exec] actions — the per_action_auth flag does NOT gate
	// trusted-.byn exec; only the .byn's own actions contract matters.
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"KEY\"]\nactions = [\"myapp\"]\n")
	grantBynFile(t, c, byn, pw)

	// No password in the request — must succeed because Path is set and "myapp" is pinned.
	resp, err := execFetch(t, c, ipc.ExecFetchReq{Path: byn, Command: "myapp", Argv: []string{"myapp"}})
	if err != nil {
		t.Fatalf("trusted exec with flag on and pinned action (no password): %v", err)
	}
	m := valueMap(resp.Values)
	if m["KEY"] != "value" {
		t.Errorf("KEY = %q, want value", m["KEY"])
	}
}

// ---- flag off: existing behaviour unchanged ----------------------------

// TestPerActionFlagOffUnchanged: with the flag off, get/put-overwrite/delete
// behave exactly as today — no auth_required anywhere.
func TestPerActionFlagOffUnchanged(t *testing.T) {
	// startTestDaemon uses Config{} — PerActionAuth defaults to false.
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Insert without password.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v1")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// Overwrite without password → should succeed (no gate).
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v2")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("overwrite no pw (flag off): %v", err)
	}
	// Get without password → should succeed.
	var gr ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY"}, &gr); err != nil {
		t.Fatalf("get no pw (flag off): %v", err)
	}
	if string(gr.Value) != "v2" {
		t.Errorf("value = %q, want v2", gr.Value)
	}
	// Delete without password → should succeed (vault is unlocked).
	if err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "KEY"}, &ipc.DeleteResp{}); err != nil {
		t.Fatalf("delete no pw (flag off, unlocked): %v", err)
	}
}

// ---- structural delete gates (project / env / vault) -------------------

// TestPerActionProjectDeleteRequiresAuth: flag on + unlocked + no creds →
// CodeAuthRequired; audit event recorded; with password → succeeds for a
// non-default target.
func TestPerActionProjectDeleteRequiresAuth(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "svc"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Fatalf("project create: %v", err)
	}

	// No creds → auth_required.
	c.Session = nil
	err := c.Call(ipc.OpProjectDelete, ipc.ProjectDeleteReq{Name: "svc"}, &ipc.ProjectDeleteResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("code = %v, want auth_required", code)
	}

	// Denied attempt must be audited.
	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 30}, &tail); err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	found := false
	for _, ev := range tail.Events {
		if ev.Op == "project.delete" && ev.Outcome == "denied" && ev.ErrorCode == string(ipc.CodeAuthRequired) {
			found = true
		}
	}
	if !found {
		t.Error("expected a denied project.delete audit event with error_code auth_required")
	}

	// With correct password → succeeds.
	if err := c.Call(ipc.OpProjectDelete, ipc.ProjectDeleteReq{Name: "svc", Password: pw}, &ipc.ProjectDeleteResp{}); err != nil {
		t.Fatalf("project delete with password: %v", err)
	}
}

// TestPerActionProjectDeleteFlagOff: flag off → project delete works credential-free
// while unlocked (today's behaviour unchanged).
func TestPerActionProjectDeleteFlagOff(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "svc"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Fatalf("project create: %v", err)
	}
	// No password → should succeed (flag off, vault unlocked).
	if err := c.Call(ipc.OpProjectDelete, ipc.ProjectDeleteReq{Name: "svc"}, &ipc.ProjectDeleteResp{}); err != nil {
		t.Fatalf("project delete no pw (flag off): %v", err)
	}
}

// TestPerActionEnvDeleteRequiresAuth: flag on + unlocked + no creds →
// CodeAuthRequired; audit event recorded; with password → succeeds.
func TestPerActionEnvDeleteRequiresAuth(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "stg"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatalf("env create: %v", err)
	}

	// No creds → auth_required.
	c.Session = nil
	err := c.Call(ipc.OpEnvDelete, ipc.EnvDeleteReq{Project: "default", Name: "stg"}, &ipc.EnvDeleteResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("code = %v, want auth_required", code)
	}

	// Denied attempt must be audited.
	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 30}, &tail); err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	found := false
	for _, ev := range tail.Events {
		if ev.Op == "env.delete" && ev.Outcome == "denied" && ev.ErrorCode == string(ipc.CodeAuthRequired) {
			found = true
		}
	}
	if !found {
		t.Error("expected a denied env.delete audit event with error_code auth_required")
	}

	// With correct password → succeeds.
	if err := c.Call(ipc.OpEnvDelete, ipc.EnvDeleteReq{Project: "default", Name: "stg", Password: pw}, &ipc.EnvDeleteResp{}); err != nil {
		t.Fatalf("env delete with password: %v", err)
	}
}

// TestPerActionEnvDeleteFlagOff: flag off → env delete works credential-free
// while unlocked (today's behaviour unchanged).
func TestPerActionEnvDeleteFlagOff(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "stg"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatalf("env create: %v", err)
	}
	// No password → should succeed (flag off, vault unlocked).
	if err := c.Call(ipc.OpEnvDelete, ipc.EnvDeleteReq{Project: "default", Name: "stg"}, &ipc.EnvDeleteResp{}); err != nil {
		t.Fatalf("env delete no pw (flag off): %v", err)
	}
}

// TestPerActionVaultDeleteRequiresAuth: flag on + unlocked non-default vault
// + no creds → CodeAuthRequired; audit event recorded; with password → succeeds.
func TestPerActionVaultDeleteRequiresAuth(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	// Create and unlock a second (non-default) vault.
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Name: "acme", Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("vault init acme: %v", err)
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Name: "acme", Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("vault unlock acme: %v", err)
	}

	// No creds → auth_required.
	err := c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: "acme"}, &ipc.VaultDeleteResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("code = %v, want auth_required", code)
	}

	// Denied attempt must be audited.
	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Vault: "acme", Lines: 30}, &tail); err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	found := false
	for _, ev := range tail.Events {
		if ev.Op == "vault.delete" && ev.Outcome == "denied" && ev.ErrorCode == string(ipc.CodeAuthRequired) {
			found = true
		}
	}
	if !found {
		t.Error("expected a denied vault.delete audit event with error_code auth_required")
	}

	// With correct password → succeeds.
	if err := c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: "acme", Password: pw}, &ipc.VaultDeleteResp{}); err != nil {
		t.Fatalf("vault delete with password: %v", err)
	}
}

// TestPerActionVaultDeleteFlagOff: flag off → vault delete works credential-free
// while unlocked (today's behaviour unchanged).
func TestPerActionVaultDeleteFlagOff(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Name: "acme", Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("vault init acme: %v", err)
	}
	var acmeUnlockRespDFO ipc.VaultUnlockResp
	acmeTokDFO, unlockErrDFO := c.CallAndCaptureSession(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Name: "acme", Password: pw}, &acmeUnlockRespDFO, nil)
	if unlockErrDFO != nil {
		t.Fatalf("vault unlock acme: %v", unlockErrDFO)
	}
	c.Session = acmeTokDFO
	// No password → should succeed (flag off, vault unlocked).
	if err := c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: "acme", Password: pw}, &ipc.VaultDeleteResp{}); err != nil {
		t.Fatalf("vault delete no pw (flag off): %v", err)
	}
}

// TestVaultDelete_SessionOnly_Rejected: vault.delete ALWAYS requires fresh
// credentials — a valid session for the target vault is NOT sufficient.
// This pins the spec-review finding: vault.delete is no longer session-blessable.
func TestVaultDelete_SessionOnly_Rejected(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Create and unlock a second vault, capturing its session token.
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Name: "acme", Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("vault init acme: %v", err)
	}
	var acmeUnlockResp ipc.VaultUnlockResp
	acmeTok, err := c.CallAndCaptureSession(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Name: "acme", Password: pw}, &acmeUnlockResp, nil)
	if err != nil {
		t.Fatalf("vault unlock acme: %v", err)
	}
	// Set the client session to the "acme" vault session — this is a valid
	// session for the exact target vault. vault.delete must still reject it.
	c.Session = acmeTok

	// Session set for target vault, no password → auth_required (session is
	// explicitly insufficient for vault.delete; fresh credentials required).
	err = c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: "acme"}, &ipc.VaultDeleteResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("vault.delete with valid session: code = %v, want auth_required (session not sufficient)", code)
	}

	// Unlocked vault + no password → still auth_required.
	// (The vault is already unlocked from the unlock above; session is set.)
	c.Session = nil
	err = c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: "acme"}, &ipc.VaultDeleteResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("vault.delete unlocked + no password: code = %v, want auth_required", code)
	}

	// Correct password → deleted.
	if err := c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: "acme", Password: pw}, &ipc.VaultDeleteResp{}); err != nil {
		t.Fatalf("vault.delete with correct password: %v", err)
	}
}

// TestVaultDelete_PresenceToken_Succeeds: a valid presence token (passkey flow)
// authorizes vault.delete — presence tokens are accepted by authorizeActionAlways.
func TestVaultDelete_PresenceToken_Succeeds(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Name: "acme2", Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("vault init acme2: %v", err)
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Name: "acme2", Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("vault unlock acme2: %v", err)
	}

	tok, err := d.presenceTokens.mint("acme2", time.Now())
	if err != nil {
		t.Fatalf("mint presence token: %v", err)
	}

	// No password, but valid presence token → succeeds.
	c.Session = nil
	if err := c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: "acme2", PresenceToken: tok}, &ipc.VaultDeleteResp{}); err != nil {
		t.Fatalf("vault.delete with presence token: %v", err)
	}
}

// ---- vault rename gate -------------------------------------------------

// TestPerActionVaultRenameRequiresAuth: flag on + unlocked non-default vault
// + no creds → CodeAuthRequired; audit event recorded; with password → renamed.
func TestPerActionVaultRenameRequiresAuth(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	// Create and unlock a second (non-default) vault.
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Name: "acme", Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("vault init acme: %v", err)
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Name: "acme", Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("vault unlock acme: %v", err)
	}

	// No creds → auth_required.
	err := c.Call(ipc.OpVaultRename, ipc.VaultRenameReq{OldName: "acme", NewName: "brand"}, &ipc.VaultRenameResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("no-creds code = %v, want auth_required", code)
	}

	// Denied attempt must be audited (emitted to the "acme" vault's audit log).
	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Vault: "acme", Lines: 30}, &tail); err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	foundDenied := false
	for _, ev := range tail.Events {
		if ev.Op == "vault.rename" && ev.Outcome == "denied" && ev.ErrorCode == string(ipc.CodeAuthRequired) {
			foundDenied = true
		}
	}
	if !foundDenied {
		t.Error("expected a denied vault.rename audit event with error_code auth_required")
	}

	// With correct password → renamed.
	if err := c.Call(ipc.OpVaultRename,
		ipc.VaultRenameReq{OldName: "acme", NewName: "brand", Password: pw}, &ipc.VaultRenameResp{}); err != nil {
		t.Fatalf("vault rename with password: %v", err)
	}

	// Verify via vault list.
	var listResp ipc.VaultListResp
	if err := c.Call(ipc.OpVaultList, ipc.VaultListReq{}, &listResp); err != nil {
		t.Fatalf("vault list: %v", err)
	}
	names := make(map[string]bool)
	for _, v := range listResp.Vaults {
		names[v.Name] = true
	}
	if !names["brand"] {
		t.Error("brand not found after rename")
	}
	if names["acme"] {
		t.Error("acme still present after rename")
	}
}

// TestPerActionVaultRenameFlagOff: flag off → vault rename works credential-free
// while unlocked (existing behaviour unchanged).
func TestPerActionVaultRenameFlagOff(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Name: "acme", Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("vault init acme: %v", err)
	}
	var acmeUnlockRespFO ipc.VaultUnlockResp
	acmeTokFO, unlockErrFO := c.CallAndCaptureSession(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Name: "acme", Password: pw}, &acmeUnlockRespFO, nil)
	if unlockErrFO != nil {
		t.Fatalf("vault unlock acme: %v", unlockErrFO)
	}
	c.Session = acmeTokFO
	// No password → should succeed (flag off, vault unlocked).
	if err := c.Call(ipc.OpVaultRename, ipc.VaultRenameReq{OldName: "acme", NewName: "brand", Password: pw}, &ipc.VaultRenameResp{}); err != nil {
		t.Fatalf("vault rename no pw (flag off): %v", err)
	}

	// Confirm rename happened.
	var listResp ipc.VaultListResp
	if err := c.Call(ipc.OpVaultList, ipc.VaultListReq{}, &listResp); err != nil {
		t.Fatalf("vault list: %v", err)
	}
	names := make(map[string]bool)
	for _, v := range listResp.Vaults {
		names[v.Name] = true
	}
	if !names["brand"] {
		t.Error("brand not found after flag-off rename")
	}
	if names["acme"] {
		t.Error("acme still present after flag-off rename")
	}
}

// ---- reload test -------------------------------------------------------

// TestPerActionReloadDeprecatedFlagIgnored: the deprecated [security]
// per_action_auth flag is parsed and a warning is logged, but it does NOT
// change the authorization behavior — the NU-3 session-based matrix is
// always active regardless of the flag value. Reload succeeds and returns no
// change note for the deprecated key.
func TestPerActionReloadDeprecatedFlagIgnored(t *testing.T) {
	dir := shortTempDir(t)
	d := startBareDaemon(t, Config{Dir: dir})
	c := ipc.NewClient(d.SocketPath())
	pw := []byte(authzPW)
	initUnlocked(t, c, pw) // captures session into c.Session

	// Seed an entry.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	// Session is set — get should work (session satisfies the gate).
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY"}, &ipc.GetResp{}); err != nil {
		t.Fatalf("get with session: %v", err)
	}

	// Write per_action_auth = true into config and reload.
	// The flag is deprecated and ignored; Reload must succeed and NOT emit
	// a "per_action_auth enabled/disabled" change note.
	writeConfig(t, dir, "[security]\nper_action_auth = true\n")
	changes, err := d.Reload()
	if err != nil {
		t.Fatalf("Reload with deprecated flag: %v", err)
	}
	for _, ch := range changes {
		if ch == "per_action_auth enabled" || ch == "per_action_auth disabled" {
			t.Errorf("Reload emitted deprecated change note %q; flag is a no-op", ch)
		}
	}

	// Session still valid — get must still succeed (flag does not affect behavior).
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY"}, &ipc.GetResp{}); err != nil {
		t.Fatalf("get after reload with deprecated flag=true: %v", err)
	}

	// Get WITHOUT a session → auth_required (matrix always on).
	freshClient := ipc.NewClient(d.SocketPath()) // no session
	err = freshClient.Call(ipc.OpGet, ipc.GetReq{Name: "KEY"}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("no-session get: code = %v, want auth_required (matrix always on)", code)
	}

	// Write per_action_auth = false and reload again — still no change note.
	writeConfig(t, dir, "[security]\nper_action_auth = false\n")
	changes, err = d.Reload()
	if err != nil {
		t.Fatalf("Reload with flag=false: %v", err)
	}
	for _, ch := range changes {
		if ch == "per_action_auth enabled" || ch == "per_action_auth disabled" {
			t.Errorf("Reload flag=false emitted deprecated change note %q", ch)
		}
	}

	// Session still works after reload with flag=false.
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY"}, &ipc.GetResp{}); err != nil {
		t.Fatalf("get after reload flag=false: %v", err)
	}
}
