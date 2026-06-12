package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/vault"
)

func TestVaultRename_Unlocked(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	initNamedLocked(t, c, "acme", pw)
	var acmeUnlockResp ipc.VaultUnlockResp
	acmeTok, unlockErr := c.CallAndCaptureSession(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Name: "acme", Password: pw}, &acmeUnlockResp, nil)
	if unlockErr != nil {
		t.Fatalf("unlock acme: %v", unlockErr)
	}
	c.Session = acmeTok
	if err := c.Call(ipc.OpVaultRename, ipc.VaultRenameReq{OldName: "acme", NewName: "brand"}, &ipc.VaultRenameResp{}); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := os.Stat(vault.Dir(d.cfg.Dir, "acme")); !os.IsNotExist(err) {
		t.Errorf("old dir still present: %v", err)
	}
	if _, err := os.Stat(vault.Dir(d.cfg.Dir, "brand")); err != nil {
		t.Errorf("new dir missing: %v", err)
	}
	// Rename evicts the store, so the renamed vault is now LOCKED; it
	// unlocks with the same password.
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Name: "brand", Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("unlock brand after rename: %v", err)
	}
}

func TestVaultRename_LockedWithPassword(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	initNamedLocked(t, c, "acme", pw) // stays locked

	if err := c.Call(ipc.OpVaultRename,
		ipc.VaultRenameReq{OldName: "acme", NewName: "brand", Password: pw}, &ipc.VaultRenameResp{}); err != nil {
		t.Fatalf("rename while locked: %v", err)
	}
	if _, err := os.Stat(vault.Dir(d.cfg.Dir, "brand")); err != nil {
		t.Errorf("new dir missing: %v", err)
	}
}

func TestVaultRename_LockedNoPassword(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	initNamedLocked(t, c, "acme", pw)

	err := c.Call(ipc.OpVaultRename, ipc.VaultRenameReq{OldName: "acme", NewName: "brand"}, &ipc.VaultRenameResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("code = %v, want locked", code)
	}
	if _, err := os.Stat(vault.Dir(d.cfg.Dir, "acme")); err != nil {
		t.Errorf("acme renamed despite missing password: %v", err)
	}
}

func TestVaultRename_RefusesDefault(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	err := c.Call(ipc.OpVaultRename, ipc.VaultRenameReq{OldName: "default", NewName: "other"}, &ipc.VaultRenameResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("code = %v, want bad_request", code)
	}
}

func TestVaultRename_DestExists(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	initNamedLocked(t, c, "acme", pw)
	initNamedLocked(t, c, "beta", pw)
	err := c.Call(ipc.OpVaultRename,
		ipc.VaultRenameReq{OldName: "acme", NewName: "beta", Password: pw}, &ipc.VaultRenameResp{})
	if code := errCode(t, err); code != ipc.CodeVaultExists {
		t.Fatalf("code = %v, want vault_exists", code)
	}
}

func TestProjectRename_LockedWithPassword(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "svc"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Fatalf("create: %v", err)
	}
	lockVaultStore(t, d, "default")
	// Clear session so the no-password probe has no auth context.
	c.Session = nil

	// No session and no password → auth_required (authorizeAction fires before
	// the lock check — does not reveal vault lock state to unauthenticated callers).
	err := c.Call(ipc.OpProjectRename, ipc.ProjectRenameReq{OldName: "svc", NewName: "svc2"}, &ipc.ProjectRenameResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("no-password code = %v, want auth_required", code)
	}
	// With password → renamed, vault stays locked.
	if err := c.Call(ipc.OpProjectRename,
		ipc.ProjectRenameReq{OldName: "svc", NewName: "svc2", Password: pw}, &ipc.ProjectRenameResp{}); err != nil {
		t.Fatalf("authorized project rename: %v", err)
	}
	if !d.lookupVault("default").store.IsLocked() {
		t.Error("vault left unlocked after authorized project rename")
	}
}

func TestEnvRename_LockedWithPassword(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "stg"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatalf("create: %v", err)
	}
	lockVaultStore(t, d, "default")

	if err := c.Call(ipc.OpEnvRename,
		ipc.EnvRenameReq{Project: "default", OldName: "stg", NewName: "stg2", Password: pw}, &ipc.EnvRenameResp{}); err != nil {
		t.Fatalf("authorized env rename: %v", err)
	}
	if !d.lookupVault("default").store.IsLocked() {
		t.Error("vault left unlocked after authorized env rename")
	}
}

// ---- NU-3 session matrix: project rename -----------------------------------

// TestProjectRename_UnlockedNoSession verifies that a session-free, credential-free
// caller cannot rename a project even on an UNLOCKED vault — the authorizeAction
// gate returns CodeAuthRequired rather than silently succeeding.
func TestProjectRename_UnlockedNoSession(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	// Create project while unlocked (session set by initUnlocked).
	if err := c.Call(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "svc"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Clear session — caller has no auth context.
	c.Session = nil
	err := c.Call(ipc.OpProjectRename, ipc.ProjectRenameReq{OldName: "svc", NewName: "svc2"}, &ipc.ProjectRenameResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("unlocked+no-session code = %v, want auth_required", code)
	}
}

// TestProjectRename_UnlockedWithSession verifies that a valid session satisfies
// the NU-3 gate for project rename on an unlocked vault.
func TestProjectRename_UnlockedWithSession(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	// session is set in c.Session by initUnlocked; project create is free.
	if err := c.Call(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "svc"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Session is still set — rename must succeed without a password.
	if err := c.Call(ipc.OpProjectRename, ipc.ProjectRenameReq{OldName: "svc", NewName: "svc2"}, &ipc.ProjectRenameResp{}); err != nil {
		t.Fatalf("project rename with session: %v", err)
	}
}

// TestProjectRename_UnlockedWithPassword verifies that a fresh password satisfies
// the NU-3 gate for project rename on an unlocked vault when no session is present.
func TestProjectRename_UnlockedWithPassword(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "svc"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Drop session — must fall back to password auth.
	c.Session = nil
	if err := c.Call(ipc.OpProjectRename,
		ipc.ProjectRenameReq{OldName: "svc", NewName: "svc2", Password: pw}, &ipc.ProjectRenameResp{}); err != nil {
		t.Fatalf("project rename with password: %v", err)
	}
}

// ---- NU-3 session matrix: env rename ---------------------------------------

// TestEnvRename_UnlockedNoSession verifies that a session-free, credential-free
// caller cannot rename an env even on an UNLOCKED vault.
func TestEnvRename_UnlockedNoSession(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "stg"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Clear session — caller has no auth context.
	c.Session = nil
	err := c.Call(ipc.OpEnvRename, ipc.EnvRenameReq{Project: "default", OldName: "stg", NewName: "staging"}, &ipc.EnvRenameResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("unlocked+no-session code = %v, want auth_required", code)
	}
}

// TestEnvRename_UnlockedWithSession verifies that a valid session satisfies
// the NU-3 gate for env rename on an unlocked vault.
func TestEnvRename_UnlockedWithSession(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "stg"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Session is still set by initUnlocked — rename must succeed.
	if err := c.Call(ipc.OpEnvRename,
		ipc.EnvRenameReq{Project: "default", OldName: "stg", NewName: "staging"}, &ipc.EnvRenameResp{}); err != nil {
		t.Fatalf("env rename with session: %v", err)
	}
}

// TestEnvRename_UnlockedWithPassword verifies that a fresh password satisfies
// the NU-3 gate for env rename on an unlocked vault when no session is present.
func TestEnvRename_UnlockedWithPassword(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "stg"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Drop session — must fall back to password auth.
	c.Session = nil
	if err := c.Call(ipc.OpEnvRename,
		ipc.EnvRenameReq{Project: "default", OldName: "stg", NewName: "staging", Password: pw}, &ipc.EnvRenameResp{}); err != nil {
		t.Fatalf("env rename with password: %v", err)
	}
}

func TestVaultRename_AuditFollows(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	initNamedLocked(t, c, "acme", pw)

	if err := c.Call(ipc.OpVaultRename,
		ipc.VaultRenameReq{OldName: "acme", NewName: "brand", Password: pw}, &ipc.VaultRenameResp{}); err != nil {
		t.Fatalf("rename: %v", err)
	}
	// The audit trail moved with the vault and carries the rename event.
	newAudit := filepath.Join(d.cfg.Dir, "audit", "brand")
	if _, err := os.Stat(newAudit); err != nil {
		t.Errorf("audit dir did not follow the rename: %v", err)
	}
	if _, err := os.Stat(filepath.Join(d.cfg.Dir, "audit", "acme")); !os.IsNotExist(err) {
		t.Errorf("old audit dir still present: %v", err)
	}
}
