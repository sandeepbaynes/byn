package daemon

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/config"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

// ---- sessionStore unit tests -----------------------------------------------

func TestSessionStore_MintAndValidate_HappyPath(t *testing.T) {
	t0 := time.Now()
	s := newSessionStore(12*time.Hour, 15*time.Minute)
	tok := s.mint("default", "cli", 1000, 42, t0)
	if tok == "" {
		t.Fatal("mint returned empty token")
	}
	if len(tok) != 64 { // 32 bytes hex-encoded
		t.Fatalf("token length = %d, want 64", len(tok))
	}
	// Verify that the token is valid hex.
	if _, err := hex.DecodeString(tok); err != nil {
		t.Fatalf("token is not hex: %v", err)
	}
	if !s.validate(tok, "default", 1000, 42, t0) {
		t.Fatal("validate returned false for a fresh token")
	}
}

func TestSessionStore_Validate_WrongVault(t *testing.T) {
	t0 := time.Now()
	s := newSessionStore(12*time.Hour, 0)
	tok := s.mint("default", "cli", 1000, 42, t0)
	if s.validate(tok, "other", 1000, 42, t0) {
		t.Fatal("validate should reject a wrong vault")
	}
}

func TestSessionStore_Validate_WrongUID(t *testing.T) {
	t0 := time.Now()
	s := newSessionStore(12*time.Hour, 0)
	tok := s.mint("default", "cli", 1000, 42, t0)
	if s.validate(tok, "default", 9999, 42, t0) {
		t.Fatal("validate should reject wrong uid")
	}
}

func TestSessionStore_Validate_WrongTTYDev(t *testing.T) {
	t0 := time.Now()
	s := newSessionStore(12*time.Hour, 0)
	tok := s.mint("default", "cli", 1000, 42, t0)
	if s.validate(tok, "default", 1000, 99, t0) {
		t.Fatal("validate should reject wrong ttyDev when stored ttyDev != 0")
	}
}

func TestSessionStore_Validate_TTYDev0_SkipCheck(t *testing.T) {
	// ttyDev=0 sessions (portal) accept any ttyDev from the same uid.
	t0 := time.Now()
	s := newSessionStore(12*time.Hour, 0)
	tok := s.mint("default", "portal", 1000, 0, t0)
	// Any ttyDev from the same uid should pass.
	if !s.validate(tok, "default", 1000, 42, t0) {
		t.Fatal("ttyDev=0 session should accept any ttyDev from matching uid")
	}
	if !s.validate(tok, "default", 1000, 0, t0) {
		t.Fatal("ttyDev=0 session should accept ttyDev=0 from matching uid")
	}
}

func TestSessionStore_Validate_EmptyToken(t *testing.T) {
	s := newSessionStore(12*time.Hour, 0)
	if s.validate("", "default", 1000, 42, time.Now()) {
		t.Fatal("empty token should not validate")
	}
}

func TestSessionStore_Validate_UnknownToken(t *testing.T) {
	s := newSessionStore(12*time.Hour, 0)
	if s.validate("deadbeef", "default", 1000, 42, time.Now()) {
		t.Fatal("unknown token should not validate")
	}
}

func TestSessionStore_TTL_Expiry(t *testing.T) {
	t0 := time.Now()
	s := newSessionStore(10*time.Minute, 0)
	tok := s.mint("default", "cli", 1000, 42, t0)
	// Not expired yet.
	if !s.validate(tok, "default", 1000, 42, t0.Add(9*time.Minute)) {
		t.Fatal("should be valid before TTL")
	}
	// Re-mint since the previous validate may have consumed nothing.
	tok2 := s.mint("default", "cli", 1000, 42, t0)
	// Expired.
	if s.validate(tok2, "default", 1000, 42, t0.Add(10*time.Minute)) {
		t.Fatal("should be expired at TTL boundary")
	}
}

func TestSessionStore_Idle_SlidingWindow(t *testing.T) {
	t0 := time.Now()
	s := newSessionStore(0, 5*time.Minute)
	tok := s.mint("default", "cli", 1000, 42, t0)

	// Validate at t0+4m: updates LastUsed.
	if !s.validate(tok, "default", 1000, 42, t0.Add(4*time.Minute)) {
		t.Fatal("should be valid at t0+4m")
	}
	// Validate at t0+8m (4m after the last successful validate): still valid
	// because the idle window slides from LastUsed, not from CreatedAt.
	if !s.validate(tok, "default", 1000, 42, t0.Add(8*time.Minute)) {
		t.Fatal("sliding window: should still be valid 4m after last use")
	}
	// Validate at t0+14m (6m after t0+8m): should be expired.
	if s.validate(tok, "default", 1000, 42, t0.Add(14*time.Minute)) {
		t.Fatal("should be expired after idle window")
	}
}

func TestSessionStore_Idle_Expiry(t *testing.T) {
	t0 := time.Now()
	s := newSessionStore(0, 5*time.Minute)
	tok := s.mint("default", "cli", 1000, 42, t0)
	// No validate in between; idle window fires.
	if s.validate(tok, "default", 1000, 42, t0.Add(5*time.Minute)) {
		t.Fatal("should be idle-expired at 5m without activity")
	}
}

func TestSessionStore_EndVault(t *testing.T) {
	t0 := time.Now()
	s := newSessionStore(0, 0)
	tok1 := s.mint("default", "cli", 1000, 42, t0)
	tok2 := s.mint("other", "cli", 1000, 42, t0)

	s.endVault("default")

	if s.validate(tok1, "default", 1000, 42, t0) {
		t.Fatal("tok1 should be ended by endVault(default)")
	}
	if !s.validate(tok2, "other", 1000, 42, t0) {
		t.Fatal("tok2 (other vault) should survive endVault(default)")
	}
}

func TestSessionStore_EndToken(t *testing.T) {
	t0 := time.Now()
	s := newSessionStore(0, 0)
	tok := s.mint("default", "cli", 1000, 42, t0)
	s.endToken(tok)
	if s.validate(tok, "default", 1000, 42, t0) {
		t.Fatal("token should be invalid after endToken")
	}
}

func TestSessionStore_EndToken_ReturnsVaultAndSurface(t *testing.T) {
	t0 := time.Now()
	s := newSessionStore(0, 0)
	tok := s.mint("myvault", "portal", 1000, 0, t0)
	vaultName, surface := s.endToken(tok)
	if vaultName != "myvault" {
		t.Errorf("endToken vaultName = %q, want %q", vaultName, "myvault")
	}
	if surface != "portal" {
		t.Errorf("endToken surface = %q, want %q", surface, "portal")
	}
}

func TestSessionStore_EndToken_AbsentReturnsEmpty(t *testing.T) {
	s := newSessionStore(0, 0)
	vaultName, surface := s.endToken("nosuchtoken")
	if vaultName != "" || surface != "" {
		t.Errorf("endToken absent token = (%q, %q), want (\"\", \"\")", vaultName, surface)
	}
}

func TestSessionStore_EndToken_Idempotent(t *testing.T) {
	t0 := time.Now()
	s := newSessionStore(0, 0)
	tok := s.mint("default", "cli", 1000, 42, t0)
	// Double-ending should not panic.
	s.endToken(tok)
	s.endToken(tok)
}

func TestSessionStore_Sweep(t *testing.T) {
	t0 := time.Now()
	// TTL=10m, idle=0 (no idle check) — tests only the absolute-TTL sweep path
	// so the idle window does not fire before the TTL check.
	s := newSessionStore(10*time.Minute, 0)
	// Mint two sessions.
	_ = s.mint("default", "cli", 1000, 42, t0)
	_ = s.mint("default", "cli", 1000, 43, t0)

	// Sweep at t0+4m: both sessions are within TTL (10m) — nothing removed.
	n := s.sweep(t0.Add(4 * time.Minute))
	if n != 0 {
		t.Fatalf("sweep at 4m removed %d sessions, want 0", n)
	}

	// Sweep at t0+11m: both sessions exceed TTL of 10m — both removed.
	n = s.sweep(t0.Add(11 * time.Minute))
	if n != 2 {
		t.Errorf("sweep at 11m removed %d sessions, want 2", n)
	}
}

// ---- Dispatch-level tests --------------------------------------------------

func TestHandleVaultUnlock_ReturnsSessionToken(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("unlock-session-pw")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("init: %v", err)
	}
	var resp ipc.VaultUnlockResp
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &resp); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if len(resp.SessionToken) == 0 {
		t.Fatal("unlock response must carry a session token")
	}
	if len(resp.SessionToken) != 64 {
		t.Fatalf("session token length = %d, want 64 (32 bytes hex)", len(resp.SessionToken))
	}
}

func TestHandleVaultUnlock_EnvelopeCarriesSession(t *testing.T) {
	// The session token must also appear in Envelope.Session (the envelope header
	// field), not just the response body.
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pw := []byte("env-session-pw")
	// Init via dispatch.
	env := mustMakeEnv(t, ipc.OpVaultInit, ipc.VaultInitReq{Password: pw})
	initResp := d.Dispatch(newPortalCtx(t, d), env)
	if initResp.Err != nil {
		t.Fatalf("init: %v", initResp.Err)
	}
	// Unlock via dispatch — check envelope Session field.
	unlockEnv := mustMakeEnv(t, ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw})
	unlockResp := d.Dispatch(newPortalCtx(t, d), unlockEnv)
	if unlockResp.Err != nil {
		t.Fatalf("unlock: %v", unlockResp.Err)
	}
	if len(unlockResp.Session) == 0 {
		t.Fatal("unlock envelope must carry Session in the header")
	}
	// Verify the token in the header matches the token in the body.
	var bodyResp ipc.VaultUnlockResp
	if err := json.Unmarshal(unlockResp.Resp, &bodyResp); err != nil {
		t.Fatalf("decode resp body: %v", err)
	}
	if string(unlockResp.Session) != string(bodyResp.SessionToken) {
		t.Fatalf("envelope Session %q != body SessionToken %q",
			unlockResp.Session, bodyResp.SessionToken)
	}
}

func TestHandleVaultLock_KillsSessions(t *testing.T) {
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pw := []byte("lock-kill-pw")
	initEnv := mustMakeEnv(t, ipc.OpVaultInit, ipc.VaultInitReq{Password: pw})
	if resp := d.Dispatch(newPortalCtx(t, d), initEnv); resp.Err != nil {
		t.Fatalf("init: %v", resp.Err)
	}
	unlockEnv := mustMakeEnv(t, ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw})
	unlockResp := d.Dispatch(newPortalCtx(t, d), unlockEnv)
	if unlockResp.Err != nil {
		t.Fatalf("unlock: %v", unlockResp.Err)
	}
	tok := string(unlockResp.Session)
	if tok == "" {
		t.Fatal("no session token after unlock")
	}

	// Session should be valid right now.
	if !d.sessions.validate(tok, "default", d.ownerUID, 0, time.Now()) {
		t.Fatal("session should be valid before lock")
	}

	// Lock the vault.
	lockEnv := mustMakeEnv(t, ipc.OpVaultLock, ipc.VaultLockReq{Name: "default"})
	if resp := d.Dispatch(newPortalCtx(t, d), lockEnv); resp.Err != nil {
		t.Fatalf("lock: %v", resp.Err)
	}

	// Session must now be invalid.
	if d.sessions.validate(tok, "default", d.ownerUID, 0, time.Now()) {
		t.Fatal("session should be invalid after lock")
	}
}

func TestHandlePasskeyAuthFinish_UnlockedMintsPortalSession(t *testing.T) {
	// Simulate a passkey auth finish that results in Unlocked=true by using
	// the daemon's internal session store directly, since we cannot run a full
	// WebAuthn ceremony in a unit test. Instead we verify that mintSessionForPortal
	// is called correctly and produces a valid token.
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pw := []byte("passkey-session-pw")
	initEnv := mustMakeEnv(t, ipc.OpVaultInit, ipc.VaultInitReq{Password: pw})
	ctx := newPortalCtx(t, d)
	if resp := d.Dispatch(ctx, initEnv); resp.Err != nil {
		t.Fatalf("init: %v", resp.Err)
	}
	// Unlock via password to make the vault unlocked (simulates the passkey
	// cold-unlock landing path without a real WebAuthn ceremony).
	unlockEnv := mustMakeEnv(t, ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw})
	if resp := d.Dispatch(ctx, unlockEnv); resp.Err != nil {
		t.Fatalf("unlock: %v", resp.Err)
	}

	// Directly call mintSessionForPortal to verify portal session minting works.
	tok := d.mintSessionForPortal("default", time.Now())
	if tok == "" {
		t.Fatal("mintSessionForPortal returned empty token")
	}
	if !d.sessions.validate(tok, "default", d.ownerUID, 0, time.Now()) {
		t.Fatal("portal session should be valid immediately after mint")
	}
	// ttyDev constraint: portal sessions accept any ttyDev (ttyDev=0 stored).
	if !d.sessions.validate(tok, "default", d.ownerUID, 42, time.Now()) {
		t.Fatal("portal session (ttyDev=0) should accept non-zero ttyDev from matching uid")
	}
}

func TestHandleSessionEnd_EndsToken(t *testing.T) {
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pw := []byte("session-end-pw")
	ctx := newPortalCtx(t, d)
	if resp := d.Dispatch(ctx, mustMakeEnv(t, ipc.OpVaultInit, ipc.VaultInitReq{Password: pw})); resp.Err != nil {
		t.Fatalf("init: %v", resp.Err)
	}
	unlockResp := d.Dispatch(ctx, mustMakeEnv(t, ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}))
	if unlockResp.Err != nil {
		t.Fatalf("unlock: %v", unlockResp.Err)
	}
	tok := string(unlockResp.Session)
	if tok == "" {
		t.Fatal("no session token after unlock")
	}

	// Validate that the session is live.
	if !d.sessions.validate(tok, "default", d.ownerUID, 0, time.Now()) {
		t.Fatal("session should be valid before session.end")
	}

	// Call session.end.
	endEnv := mustMakeEnv(t, ipc.OpSessionEnd, ipc.SessionEndReq{})
	endEnv.Session = []byte(tok)
	if resp := d.Dispatch(ctx, endEnv); resp.Err != nil {
		t.Fatalf("session.end: %v", resp.Err)
	}

	// Session must now be invalid.
	if d.sessions.validate(tok, "default", d.ownerUID, 0, time.Now()) {
		t.Fatal("session should be invalid after session.end")
	}
}

func TestHandleSessionEnd_NoToken_Idempotent(t *testing.T) {
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// session.end with no token in the envelope should succeed silently.
	endEnv := mustMakeEnv(t, ipc.OpSessionEnd, ipc.SessionEndReq{})
	// No Session set.
	if resp := d.Dispatch(newPortalCtx(t, d), endEnv); resp.Err != nil {
		t.Fatalf("session.end with no token: %v", resp.Err)
	}
}

// ---- Audit events ----------------------------------------------------------

func TestSessionAudit_MintEmitsEvent(t *testing.T) {
	// Verify that vault.unlock emits a session.mint audit event. We check the
	// audit tail for the vault after an unlock.
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte("audit-session-pw"))

	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 50}, &tail); err != nil {
		t.Fatalf("audit.tail: %v", err)
	}
	found := false
	for _, ev := range tail.Events {
		if ev.Op == "session.mint" {
			found = true
			break
		}
	}
	if !found {
		ops := make([]string, 0, len(tail.Events))
		for _, ev := range tail.Events {
			ops = append(ops, ev.Op)
		}
		t.Errorf("session.mint audit event not found; ops seen: %v", ops)
	}
}

// ---- Config defaults + parsing ---------------------------------------------

func TestConfig_SessionDefaults(t *testing.T) {
	cfg, err := config.Load("/nonexistent/path")
	if err != nil {
		// Missing file is not an error.
		t.Fatalf("config.Load missing file: %v", err)
	}
	if time.Duration(cfg.Security.SessionTTL) != config.DefaultSessionTTL {
		t.Errorf("default SessionTTL = %v, want %v",
			time.Duration(cfg.Security.SessionTTL), config.DefaultSessionTTL)
	}
	if time.Duration(cfg.Security.SessionIdle) != 0 {
		t.Errorf("default SessionIdle = %v, want 0 (inherit)", time.Duration(cfg.Security.SessionIdle))
	}
}

func TestConfig_SessionParsing(t *testing.T) {
	content := []byte(`
[security]
session_ttl = "6h"
session_idle = "30m"
`)
	cfg, err := config.Parse(content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := time.Duration(cfg.Security.SessionTTL); got != 6*time.Hour {
		t.Errorf("session_ttl = %v, want 6h", got)
	}
	if got := time.Duration(cfg.Security.SessionIdle); got != 30*time.Minute {
		t.Errorf("session_idle = %v, want 30m", got)
	}
}

// ---- Wire pin: omitempty ---------------------------------------------------

func TestEnvelope_Session_OmitEmpty(t *testing.T) {
	// An envelope with no session must not include "session" in the JSON.
	env := &ipc.Envelope{V: 2, ID: "x", Op: ipc.OpStatus}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `{"v":2,"id":"x","op":"status"}` {
		// Allow any field order but session must be absent.
		var m map[string]json.RawMessage
		_ = json.Unmarshal(b, &m)
		if _, ok := m["session"]; ok {
			t.Fatalf("session field present in wire frame with no session: %s", b)
		}
	}
}

func TestEnvelope_Session_PresentWhenSet(t *testing.T) {
	env := &ipc.Envelope{V: 2, ID: "x", Op: ipc.OpStatus, Session: []byte("abc123")}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["session"]; !ok {
		t.Fatalf("session field missing from wire frame when Session is set: %s", b)
	}
}

func TestVaultUnlockResp_SessionToken_OmitEmpty(t *testing.T) {
	resp := ipc.VaultUnlockResp{}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `{}` {
		var m map[string]json.RawMessage
		_ = json.Unmarshal(b, &m)
		if _, ok := m["session_token"]; ok {
			t.Fatalf("session_token present in empty VaultUnlockResp: %s", b)
		}
	}
}

func TestPasskeyAuthFinishResp_SessionToken_OmitEmpty(t *testing.T) {
	resp := ipc.PasskeyAuthFinishResp{CredentialID: []byte("cred")}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	if _, ok := m["session_token"]; ok {
		t.Fatalf("session_token present in PasskeyAuthFinishResp without unlock: %s", b)
	}
}

// ---- Concurrency (-race) ---------------------------------------------------

// TestSessionStore_Concurrency hammers the session store from many goroutines
// to expose data races under -race.  All operations are performed concurrently
// without any external synchronisation — correctness of individual results is
// not asserted, only absence of races and panics.
func TestSessionStore_Concurrency(t *testing.T) {
	const goroutines = 20
	const rounds = 50

	s := newSessionStore(time.Hour, 30*time.Minute)
	t0 := time.Now()

	var wg sync.WaitGroup
	for i := range goroutines {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			uid := uint32(1000 + i)
			ttyDev := int32(42 + i)
			for range rounds {
				tok := s.mint("default", "cli", uid, ttyDev, t0)
				_ = s.validate(tok, "default", uid, ttyDev, t0)
				// Interleave end/sweep to ensure concurrent delete-while-iterate safety.
				if i%3 == 0 {
					s.endToken(tok)
				}
				if i%5 == 0 {
					s.sweep(t0.Add(time.Minute))
				}
			}
		}()
	}
	wg.Wait()

	// endVault from a separate goroutine while mints may still be happening.
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.endVault("default")
	}()
	wg.Wait()
}

// ---- Session end: op registered in AllOps ----------------------------------

func TestOpSessionEnd_InAllOps(t *testing.T) {
	for _, op := range ipc.AllOps {
		if op == ipc.OpSessionEnd {
			return
		}
	}
	t.Fatalf("OpSessionEnd not in ipc.AllOps")
}

// ---- Fix 2: session.end audit on all end-of-life paths --------------------

// TestHandleVaultLock_EmitsSessionEndAudit verifies that locking a vault with
// active sessions emits one session.end audit event per ended session, with the
// surface field populated. This covers the explicit-lock code path.
func TestHandleVaultLock_EmitsSessionEndAudit(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("lock-audit-pw")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	// Lock the vault — this must end all sessions and emit session.end.
	if err := c.Call(ipc.OpVaultLock, ipc.VaultLockReq{Name: "default"}, &ipc.VaultLockResp{}); err != nil {
		t.Fatalf("lock: %v", err)
	}
	// Unlock again (needed to read audit log).
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("re-unlock: %v", err)
	}
	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 100}, &tail); err != nil {
		t.Fatalf("audit.tail: %v", err)
	}
	found := false
	for _, ev := range tail.Events {
		if ev.Op == string(ipc.OpSessionEnd) {
			found = true
			if ev.CallerSurface == "" {
				t.Errorf("session.end audit event from lock has empty CallerSurface")
			}
			break
		}
	}
	if !found {
		ops := make([]string, 0, len(tail.Events))
		for _, ev := range tail.Events {
			ops = append(ops, ev.Op)
		}
		t.Errorf("session.end audit event not found after vault lock; ops: %v", ops)
	}
}

// TestLockIdleVaults_EmitsSessionEndAudit verifies that the idle janitor emits
// session.end audit events for sessions it ends when auto-locking an idle vault.
func TestLockIdleVaults_EmitsSessionEndAudit(t *testing.T) {
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test", IdleTimeout: 15 * time.Minute})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { d.Shutdown(time.Second) })

	pw := []byte("idle-audit-pw")
	c := ipc.NewClient(d.SocketPath())
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	e := d.lookupVault("default")
	if e == nil {
		t.Fatal("no vault entry after unlock")
	}

	// Drive lockIdleVaults directly past the idle threshold so the session is ended.
	base := time.Unix(0, e.lastActive.Load())
	n := d.lockIdleVaults(base.Add(d.idleTimeoutDur() + time.Second))
	if n != 1 {
		t.Fatalf("lockIdleVaults returned %d, want 1", n)
	}

	// Re-unlock to read the audit log.
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("re-unlock: %v", err)
	}
	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 100}, &tail); err != nil {
		t.Fatalf("audit.tail: %v", err)
	}
	found := false
	for _, ev := range tail.Events {
		if ev.Op == string(ipc.OpSessionEnd) {
			found = true
			if ev.CallerSurface == "" {
				t.Errorf("session.end audit event from janitor has empty CallerSurface")
			}
			break
		}
	}
	if !found {
		ops := make([]string, 0, len(tail.Events))
		for _, ev := range tail.Events {
			ops = append(ops, ev.Op)
		}
		t.Errorf("session.end audit event not found after idle-janitor lock; ops: %v", ops)
	}
}

// TestShutdown_EmitsSessionEndAudit verifies that Shutdown emits one session.end
// audit event per live session before closing vault auditors. The audit log is
// read by starting a second daemon on the same dir after the first shuts down.
func TestShutdown_EmitsSessionEndAudit(t *testing.T) {
	dir := shortTempDir(t)
	pw := []byte("shutdown-audit-pw")

	// First daemon: init, unlock (mints a session), then shut down.
	d1, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New d1: %v", err)
	}
	ctx1, cancel1 := context.WithCancel(context.Background())
	if err := d1.Start(ctx1); err != nil {
		t.Fatalf("d1.Start: %v", err)
	}
	if resp := d1.Dispatch(ctx1, mustMakeEnv(t, ipc.OpVaultInit, ipc.VaultInitReq{Password: pw})); resp.Err != nil {
		t.Fatalf("init: %v", resp.Err)
	}
	unlockResp := d1.Dispatch(ctx1, mustMakeEnv(t, ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}))
	if unlockResp.Err != nil {
		t.Fatalf("unlock: %v", unlockResp.Err)
	}
	if len(unlockResp.Session) == 0 {
		t.Fatal("no session token minted on unlock")
	}
	// Shut down with the live session — must emit session.end before closing.
	cancel1()
	d1.Shutdown(2 * time.Second)

	// Second daemon on same dir: unlock to open the audit log, then read tail.
	d2, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New d2: %v", err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if err := d2.Start(ctx2); err != nil {
		t.Fatalf("d2.Start: %v", err)
	}
	t.Cleanup(func() { d2.Shutdown(time.Second) })
	if resp := d2.Dispatch(ctx2, mustMakeEnv(t, ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw})); resp.Err != nil {
		t.Fatalf("re-unlock on d2: %v", resp.Err)
	}
	tailResp := d2.Dispatch(ctx2, mustMakeEnv(t, ipc.OpAuditTail, ipc.AuditTailReq{Lines: 200}))
	if tailResp.Err != nil {
		t.Fatalf("audit.tail on d2: %v", tailResp.Err)
	}
	var tail ipc.AuditTailResp
	if err := ipc.DecodeBody(ipc.BodyResp, tailResp, &tail); err != nil {
		t.Fatalf("decode tail: %v", err)
	}
	found := false
	for _, ev := range tail.Events {
		if ev.Op == string(ipc.OpSessionEnd) {
			found = true
			if ev.CallerSurface == "" {
				t.Errorf("shutdown session.end audit event has empty CallerSurface")
			}
			break
		}
	}
	if !found {
		ops := make([]string, 0, len(tail.Events))
		for _, ev := range tail.Events {
			ops = append(ops, ev.Op)
		}
		t.Errorf("session.end audit event not found after Shutdown with live session; ops: %v", ops)
	}
}

// ---- Fix 3: handleSessionEnd carries caller surface -----------------------

// TestHandleSessionEnd_AuditCarriesSurface verifies that the session.end audit
// event emitted by handleSessionEnd records the caller surface rather than an
// empty string. Uses the portal Dispatch path (surface="portal") because it lets
// us attach a pre-built context with the surface stamped, mirroring what
// handleConn / Dispatch do at the real call site.
func TestHandleSessionEnd_AuditCarriesSurface(t *testing.T) {
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { d.Shutdown(time.Second) })

	pw := []byte("surface-audit-pw")
	// Init + unlock via portal path.
	if resp := d.Dispatch(ctx, mustMakeEnv(t, ipc.OpVaultInit, ipc.VaultInitReq{Password: pw})); resp.Err != nil {
		t.Fatalf("init: %v", resp.Err)
	}
	unlockEnv := mustMakeEnv(t, ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw})
	unlockResp := d.Dispatch(ctx, unlockEnv)
	if unlockResp.Err != nil {
		t.Fatalf("unlock: %v", unlockResp.Err)
	}
	tok := unlockResp.Session
	if len(tok) == 0 {
		t.Fatal("no session token after unlock")
	}

	// Build a session.end envelope with the token in the Session header — exactly
	// what the browser sends. Dispatch threads env.Session into callerInfo.Session
	// (Fix 1), so handleSessionEnd(ctx, env) will read it via callerSession(ctx).
	endEnv := mustMakeEnv(t, ipc.OpSessionEnd, ipc.SessionEndReq{})
	endEnv.Session = tok
	if resp := d.Dispatch(ctx, endEnv); resp.Err != nil {
		t.Fatalf("session.end: %v", resp.Err)
	}

	// Re-unlock to read the audit log.
	if resp := d.Dispatch(ctx, mustMakeEnv(t, ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw})); resp.Err != nil {
		t.Fatalf("re-unlock: %v", resp.Err)
	}
	tailResp := d.Dispatch(ctx, mustMakeEnv(t, ipc.OpAuditTail, ipc.AuditTailReq{Lines: 100}))
	if tailResp.Err != nil {
		t.Fatalf("audit.tail: %v", tailResp.Err)
	}
	var tail ipc.AuditTailResp
	if err := ipc.DecodeBody(ipc.BodyResp, tailResp, &tail); err != nil {
		t.Fatalf("decode tail: %v", err)
	}
	found := false
	for _, ev := range tail.Events {
		if ev.Op == string(ipc.OpSessionEnd) {
			found = true
			if ev.CallerSurface == "" {
				t.Errorf("session.end audit event has empty CallerSurface; want %q", "portal")
			}
			break
		}
	}
	if !found {
		ops := make([]string, 0, len(tail.Events))
		for _, ev := range tail.Events {
			ops = append(ops, ev.Op)
		}
		t.Errorf("session.end audit event not found; ops: %v", ops)
	}
}

// ---- helpers ---------------------------------------------------------------

// mustMakeEnv builds a request envelope for op+body. Fatals on marshal error.
func mustMakeEnv(t *testing.T, op ipc.Op, body any) *ipc.Envelope {
	t.Helper()
	env, err := ipc.NewRequest("test-id", op, body)
	if err != nil {
		t.Fatalf("ipc.NewRequest(%s): %v", op, err)
	}
	return env
}

// newPortalCtx returns a context tagged with the daemon's portal caller info,
// mirroring what Daemon.Dispatch does. No session token is set (nil).
func newPortalCtx(t *testing.T, d *Daemon) context.Context {
	t.Helper()
	return withCaller(d.handlerCtx(), d.portalCaller(nil))
}

// ---- Fix 1: callerSession accessor (Task-2 seam) ---------------------------

// TestCallerSession_PortalPath verifies that the Dispatch portal path threads
// env.Session into the handler context end-to-end. It drives d.Dispatch with a
// real minted session token on a session.end envelope, then asserts that
// Dispatch routed the token through callerInfo.Session (Fix 1 seam) and the
// handler actually ended that token (validate now false).
func TestCallerSession_PortalPath(t *testing.T) {
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { d.Shutdown(time.Second) })

	// Init + unlock via the portal Dispatch path so we get a real session token.
	pw := []byte("portal-path-pw")
	if resp := d.Dispatch(ctx, mustMakeEnv(t, ipc.OpVaultInit, ipc.VaultInitReq{Password: pw})); resp.Err != nil {
		t.Fatalf("init: %v", resp.Err)
	}
	unlockEnv := mustMakeEnv(t, ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw})
	unlockResp := d.Dispatch(ctx, unlockEnv)
	if unlockResp.Err != nil {
		t.Fatalf("unlock: %v", unlockResp.Err)
	}
	tok := unlockResp.Session
	if len(tok) == 0 {
		t.Fatal("unlock via Dispatch must return a session token in the envelope header")
	}

	// Confirm the token is valid before we end it.
	if !d.sessions.validate(string(tok), "default", d.ownerUID, 0, time.Now()) {
		t.Fatal("minted token must be valid before session.end")
	}

	// Drive Dispatch with a session.end envelope carrying the real token.
	// Dispatch threads env.Session into portalCaller (Fix 1), which stores it
	// in callerInfo.Session so handleSessionEnd can read it via callerSession(ctx).
	endEnv := mustMakeEnv(t, ipc.OpSessionEnd, ipc.SessionEndReq{})
	endEnv.Session = tok
	if resp := d.Dispatch(ctx, endEnv); resp.Err != nil {
		t.Fatalf("session.end via Dispatch: %v", resp.Err)
	}

	// The token must now be invalid — proving Dispatch threaded env.Session
	// end-to-end through the handler.
	if d.sessions.validate(string(tok), "default", d.ownerUID, 0, time.Now()) {
		t.Fatal("token must be invalid after session.end dispatched through Dispatch")
	}
}

// TestCallerSession_SocketPath verifies that a session token carried in
// Envelope.Session is threaded into callerInfo.Session by the socket-caller
// builder and can be retrieved via callerSession(ctx).
func TestCallerSession_SocketPath(t *testing.T) {
	const sentinelToken = "deadbeef11223344556677889900aabbccddeeff00112233445566778899aabb"
	tok := []byte(sentinelToken)
	ci := socketCaller(uint32(os.Getuid()), os.Getpid(), tok) //nolint:gosec
	ctx := withCaller(context.Background(), ci)
	got := callerSession(ctx)
	if string(got) != sentinelToken {
		t.Fatalf("callerSession(socketCtx) = %q, want %q", got, sentinelToken)
	}
}

// TestSessionInfo_IdleDeadline verifies that sessionInfo returns the idle
// deadline (not just the TTL deadline) when idle expires sooner (M-3/M-6).
func TestSessionInfo_IdleDeadline(t *testing.T) {
	t0 := time.Now()
	// TTL=1h, idle=10m — idle fires first.
	s := newSessionStore(time.Hour, 10*time.Minute)
	tok := s.mint("default", "cli", 1000, 42, t0)

	// sessionInfo should return the idle deadline (t0+10m), not the TTL (t0+1h).
	active, exp := s.sessionInfo(tok, "default", 1000, 42, t0)
	if !active {
		t.Fatal("session should be active")
	}
	if exp == nil {
		t.Fatal("exp must not be nil when idle is set")
	}
	want := t0.Add(10 * time.Minute)
	if !exp.Equal(want) {
		t.Errorf("exp = %v, want %v (idle deadline)", exp, want)
	}
}

// TestSessionInfo_TTLDeadline verifies that sessionInfo returns the TTL
// deadline when TTL expires sooner than idle (M-3/M-6).
func TestSessionInfo_TTLDeadline(t *testing.T) {
	t0 := time.Now()
	// TTL=5m, idle=1h — TTL fires first.
	s := newSessionStore(5*time.Minute, time.Hour)
	tok := s.mint("default", "cli", 1000, 42, t0)

	active, exp := s.sessionInfo(tok, "default", 1000, 42, t0)
	if !active {
		t.Fatal("session should be active")
	}
	if exp == nil {
		t.Fatal("exp must not be nil when TTL is set")
	}
	want := t0.Add(5 * time.Minute)
	if !exp.Equal(want) {
		t.Errorf("exp = %v, want %v (TTL deadline)", exp, want)
	}
}

// TestSessionInfo_NoTTLIdleOnly verifies that sessionInfo returns the idle
// deadline even when TTL is 0 (idle-only deployment, M-3).
func TestSessionInfo_NoTTLIdleOnly(t *testing.T) {
	t0 := time.Now()
	// TTL=0 (no abs TTL), idle=30m.
	s := newSessionStore(0, 30*time.Minute)
	tok := s.mint("default", "cli", 1000, 42, t0)

	active, exp := s.sessionInfo(tok, "default", 1000, 42, t0)
	if !active {
		t.Fatal("session should be active")
	}
	if exp == nil {
		t.Fatal("exp must not be nil for idle-only deployment")
	}
	want := t0.Add(30 * time.Minute)
	if !exp.Equal(want) {
		t.Errorf("exp = %v, want %v (idle deadline)", exp, want)
	}
}

// TestSessionInfo_InactiveSession verifies that sessionInfo returns false
// for an expired session (M-6: SessionActive annotation path).
func TestSessionInfo_InactiveSession(t *testing.T) {
	t0 := time.Now()
	s := newSessionStore(5*time.Minute, 0)
	tok := s.mint("default", "cli", 1000, 42, t0)

	// Check at expiry time — should be inactive.
	active, _ := s.sessionInfo(tok, "default", 1000, 42, t0.Add(5*time.Minute))
	if active {
		t.Fatal("expired session should not be active")
	}
}
