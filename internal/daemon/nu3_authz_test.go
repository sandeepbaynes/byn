package daemon

// nu3_authz_test.go — behavior-proof tests for NU-3 Task 2.
//
// These tests document and verify the NU-3 authorization matrix:
//
//  1. No-global-unlock proof: session satisfies gate for one caller; a caller
//     with no session token is rejected even when the vault is unlocked.
//  2. No-session get is audited as "denied" with vault.authorize op.
//  3. Policy always → session present still requires fresh credentials.
//  4. Policy none → no session, no credentials → free.
//  5. exec.fetch with NO session: trusted .byn → values flow (unchanged);
//     ad-hoc exec requires auth (sessions never bless exec).
//  6. Insert (new name) + list with no session → free.
//  7. Ended session (OpSessionEnd) → auth_required.
//  8. Expired session (short TTL) → auth_required.

import (
	"context"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// startTestDaemonWithSessionTTL is startTestDaemon with a custom SessionTTL.
func startTestDaemonWithSessionTTL(t *testing.T, ttl time.Duration) (*Daemon, *ipc.Client) {
	t.Helper()
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test", SessionTTL: ttl})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := d.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		d.Shutdown(2 * time.Second)
	})
	return d, ipc.NewClient(d.SocketPath())
}

// ---- 1. No-global-unlock proof -----------------------------------------------

// TestNU3_NoGlobalUnlock proves that a session minted for one caller does NOT
// give every caller free access to the vault. Under NU-3 there is no "global
// unlock": each caller must present its own session or fresh credentials.
//
// We simulate a second caller by clearing c.Session (the caller has no token).
// Even though the vault is unlocked, the second caller sees auth_required.
func TestNU3_NoGlobalUnlock(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("nu3-no-global")
	initUnlocked(t, c, pw) // mints session → c.Session is set

	// Seed a value (session still set → authorized).
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "SECRET", Value: []byte("gold")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	// Get WITH the session → succeeds.
	var resp ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "SECRET"}, &resp); err != nil {
		t.Fatalf("get with session: %v", err)
	}
	if string(resp.Value) != "gold" {
		t.Errorf("get with session: value = %q, want gold", resp.Value)
	}

	// Simulate a caller with NO session (cleared = never unlocked).
	// The vault is unlocked in daemon memory, but there is no global unlock:
	// this caller must authenticate independently.
	c.Session = nil
	err := c.Call(ipc.OpGet, ipc.GetReq{Name: "SECRET"}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("get without session (vault unlocked): code = %v, want auth_required", code)
	}
}

// ---- 2. No-session get is audited as denied ----------------------------------

// TestNU3_NoSessionGetAuditsDenied proves that a value-read without a session
// or credentials is logged as a denied vault.authorize event.
func TestNU3_NoSessionGetAuditsDenied(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("nu3-audit-denied")
	initUnlocked(t, c, pw)

	putVar(t, c, ipc.Scope{}, "K", []byte("v"))

	// Clear session and attempt get → auth_required.
	c.Session = nil
	err := c.Call(ipc.OpGet, ipc.GetReq{Name: "K"}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("no-session get: code = %v, want auth_required", code)
	}

	// The denial must be recorded in the audit log.
	// Re-unlock with session to read audit log.
	var ur ipc.VaultUnlockResp
	tok, unlErr := c.CallAndCaptureSession(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ur, nil)
	if unlErr != nil {
		t.Fatalf("re-unlock for audit: %v", unlErr)
	}
	c.Session = tok

	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 50}, &tail); err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	// The denied get appears as op="get" outcome="denied" error_code="auth_required".
	found := false
	for _, ev := range tail.Events {
		if ev.Op == "get" && ev.Outcome == "denied" && ev.ErrorCode == string(ipc.CodeAuthRequired) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a denied get audit event (auth_required); events: %+v", tail.Events)
	}
}

// ---- 3. Policy always → session does NOT satisfy ----------------------------

// TestNU3_PolicyAlways_SessionIgnored proves that [auth] policy="always" on a
// trusted .byn file requires FRESH credentials even when the caller has a valid
// session. The session must not satisfy a policy=always gate.
func TestNU3_PolicyAlways_SessionIgnored(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("nu3-policy-always")
	initUnlocked(t, c, pw) // c.Session is set

	putVar(t, c, ipc.Scope{}, "GUARDED", []byte("private"))

	// Trust a .byn that marks delete as "always" (unconditional fresh auth).
	p := writeByn(t, "[scope]\n\n[auth]\ndelete = \"always\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("trust grant: %v", err)
	}

	// Delete WITH a session but NO password → auth_required (policy=always
	// overrides the session; fresh credentials are always required).
	err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "GUARDED"}, &ipc.DeleteResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("delete policy=always, session set, no password: code = %v, want auth_required", code)
	}

	// Delete WITH session AND correct password → succeeds.
	if err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "GUARDED", Password: pw}, &ipc.DeleteResp{}); err != nil {
		t.Fatalf("delete policy=always with session+password: %v", err)
	}
}

// ---- 4. Policy none → no session, no credentials → free ---------------------

// TestNU3_PolicyNone_NoAuthNeeded proves that [auth] policy="none" on a
// trusted .byn file makes the operation unconditionally free: neither a
// session nor credentials are required.
func TestNU3_PolicyNone_NoAuthNeeded(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("nu3-policy-none")
	initUnlocked(t, c, pw) // needed to write the value and grant trust

	putVar(t, c, ipc.Scope{}, "CI_TOKEN", []byte("ci-val"))

	// Trust a .byn with get="none".
	p := writeByn(t, "[scope]\n\n[auth]\nget = \"none\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("trust grant: %v", err)
	}

	// Clear the session: now there is absolutely no auth context.
	c.Session = nil

	// Get without any credentials → free (policy="none").
	var resp ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "CI_TOKEN"}, &resp); err != nil {
		t.Fatalf("get with policy=none (no session, no password): %v", err)
	}
	if string(resp.Value) != "ci-val" {
		t.Errorf("policy=none get: value = %q, want ci-val", resp.Value)
	}
}

// ---- 5. exec.fetch: trusted .byn flows; ad-hoc always requires auth ---------

// TestNU3_ExecFetch_TrustedByn_NoSession proves that exec.fetch from a
// trusted .byn directory works without a session. The .byn trust model is
// path-and-scope based; sessions are not required.
func TestNU3_ExecFetch_TrustedByn_NoSession(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("nu3-exec-trusted")
	initUnlocked(t, c, pw)

	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "DB_URL", Value: []byte("postgres://localhost/db")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	// Write a .byn that grants exec access and register it.
	bynContent := "[scope]\n\n[exec]\nenv = [\"DB_URL\"]\nactions = \"*\"\n"
	p := writeBynContent(t, bynContent)
	grantBynFile(t, c, p, pw)

	// Clear the session: exec.fetch from a trusted .byn must not require one.
	c.Session = nil

	fetchResp, fetchErr := execFetch(t, c, ipc.ExecFetchReq{Path: p, Command: "myapp", Argv: []string{"myapp"}})
	if fetchErr != nil {
		t.Fatalf("exec.fetch with trusted .byn (no session): %v", fetchErr)
	}
	m := valueMap(fetchResp.Values)
	if _, ok := m["DB_URL"]; !ok {
		t.Errorf("exec.fetch: DB_URL not in values: %v", fetchResp.Values)
	}
}

// TestNU3_ExecFetch_AdHoc_RequiresAuth proves that ad-hoc exec (no .byn path)
// requires fresh credentials even when the caller has a valid session.
// Sessions never bless exec.
func TestNU3_ExecFetch_AdHoc_RequiresAuth(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("nu3-exec-adhoc")
	initUnlocked(t, c, pw) // c.Session is set

	putVar(t, c, ipc.Scope{}, "K", []byte("v"))

	// Ad-hoc exec with a valid session but no .byn path → auth_required.
	err := c.Call(ipc.OpExecFetch, ipc.ExecFetchReq{}, &ipc.ExecFetchResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("ad-hoc exec with session: code = %v, want auth_required", code)
	}

	// Without a session either → also auth_required.
	c.Session = nil
	err = c.Call(ipc.OpExecFetch, ipc.ExecFetchReq{}, &ipc.ExecFetchResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("ad-hoc exec no session: code = %v, want auth_required", code)
	}
}

// ---- 6. Insert + list with no session → free --------------------------------

// TestNU3_InsertAndList_NoSessionFree proves that inserting a brand-new name
// and listing names are free operations that require no session or credentials.
// Only reading values and overwriting existing entries are gated.
func TestNU3_InsertAndList_NoSessionFree(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("nu3-insert-free")
	initUnlocked(t, c, pw)

	// Clear the session: insert and list must be free.
	c.Session = nil

	// Insert a brand-new name → free.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "NEW_FREE_KEY", Value: []byte("val")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("insert without session: %v (should be free)", err)
	}

	// List names → free (names only, no values).
	var lr ipc.ListResp
	if err := c.Call(ipc.OpList, ipc.ListReq{}, &lr); err != nil {
		t.Fatalf("list without session: %v (should be free)", err)
	}
	found := false
	for _, s := range lr.Secrets {
		if s.Name == "NEW_FREE_KEY" {
			found = true
		}
	}
	if !found {
		t.Errorf("inserted key not visible in list: %+v", lr.Secrets)
	}
}

// ---- 7. Ended session → auth_required ----------------------------------------

// TestNU3_EndedSession_AuthRequired proves that after a session is explicitly
// ended via OpSessionEnd, subsequent operations with the old token are rejected.
func TestNU3_EndedSession_AuthRequired(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("nu3-session-end")
	initUnlocked(t, c, pw) // c.Session is set

	putVar(t, c, ipc.Scope{}, "VAL", []byte("secret"))

	// Verify the session is active: get should succeed.
	var resp ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "VAL"}, &resp); err != nil {
		t.Fatalf("get with active session: %v", err)
	}

	// End the session (equivalent to `byn unlock --end`).
	if err := c.Call(ipc.OpSessionEnd, ipc.SessionEndReq{}, &ipc.SessionEndResp{}); err != nil {
		t.Fatalf("session.end: %v", err)
	}

	// The old token is now invalid. Get returns auth_required.
	err := c.Call(ipc.OpGet, ipc.GetReq{Name: "VAL"}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("get after session.end: code = %v, want auth_required", code)
	}
}

// ---- 8. Expired session (TTL) → auth_required --------------------------------

// TestNU3_ExpiredSession_AuthRequired proves that a session whose absolute TTL
// has elapsed is rejected as invalid, returning auth_required.
// We use a daemon with SessionTTL=1ns so the token expires immediately.
func TestNU3_ExpiredSession_AuthRequired(t *testing.T) {
	// 1ns TTL: token expires almost immediately.
	_, c := startTestDaemonWithSessionTTL(t, 1)

	pw := []byte("nu3-ttl-expire")
	initUnlocked(t, c, pw) // mints token, stores in c.Session
	putVar(t, c, ipc.Scope{}, "KEY", []byte("v"))

	// Tiny sleep to guarantee the 1ns TTL has elapsed.
	time.Sleep(time.Millisecond)

	// Session token is still in c.Session but is now expired.
	err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY"}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("get with expired session (TTL=1ns): code = %v, want auth_required", code)
	}
}
