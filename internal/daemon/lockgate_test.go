package daemon

import (
	"errors"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// TestScopeMutations_RequireUnlock proves SPEC §4.2.2: structural mutations
// on a locked vault return CodeLocked, while metadata reads (list) still
// work. Init leaves the vault locked.
func TestScopeMutations_RequireUnlock(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("correct-horse")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Metadata reads remain allowed while locked.
	if err := c.Call(ipc.OpProjectList, ipc.ProjectListReq{}, &ipc.ProjectListResp{}); err != nil {
		t.Errorf("project list while locked = %v, want allowed", err)
	}
	if err := c.Call(ipc.OpEnvList, ipc.EnvListReq{Project: "default"}, &ipc.EnvListResp{}); err != nil {
		t.Errorf("env list while locked = %v, want allowed", err)
	}

	mustLocked := func(op ipc.Op, req any) {
		t.Helper()
		err := c.Call(op, req, &struct{}{})
		var e *ipc.ErrResponse
		if !errors.As(err, &e) || e.Code != ipc.CodeLocked {
			t.Errorf("%s while locked: err=%v, want CodeLocked", op, err)
		}
	}
	// mustAuthRequired asserts that an op without a session on a locked vault
	// returns auth_required (the NU-3 gate fires before the lock check for
	// operations routed through authorizeAction).
	mustAuthRequired := func(op ipc.Op, req any) {
		t.Helper()
		err := c.Call(op, req, &struct{}{})
		var e *ipc.ErrResponse
		if !errors.As(err, &e) || e.Code != ipc.CodeAuthRequired {
			t.Errorf("%s while locked (no session): err=%v, want auth_required", op, err)
		}
	}
	mustLocked(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "p"})
	mustLocked(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "e"})
	// project.delete and env.delete are routed through authorizeAction (NU-3
	// gate). With no session on a locked vault, the gate fires first and returns
	// auth_required rather than CodeLocked — this is the correct new behavior:
	// the daemon does not reveal vault lock state to unauthenticated callers.
	mustAuthRequired(ipc.OpProjectDelete, ipc.ProjectDeleteReq{Name: "p"})
	mustAuthRequired(ipc.OpEnvDelete, ipc.EnvDeleteReq{Project: "default", Name: "e"})
	// project.rename and env.rename are now routed through authorizeAction
	// (NU-3 gate). With no session on a locked vault, the gate fires first
	// and returns auth_required — not CodeLocked — so the daemon does not
	// reveal vault lock state to unauthenticated callers.
	mustAuthRequired(ipc.OpProjectRename, ipc.ProjectRenameReq{OldName: "svc", NewName: "x"})
	mustAuthRequired(ipc.OpEnvRename, ipc.EnvRenameReq{Project: "default", OldName: "default", NewName: "x"})

	// After unlock, a structural mutation succeeds.
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := c.Call(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "p"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Errorf("project create after unlock = %v, want success", err)
	}
}

// TestEntryOps_LockSemantics proves byn's core promise: `list` (env-var
// NAMES, no values) works on a locked vault, while value reads (`get`) and
// mutations (`put`/`delete`/`rename`) require authorization.
//
// Under NU-3, value-touching ops are gated by authorizeAction which fires
// BEFORE the vault lock check. With no session and no password the gate
// returns auth_required — not CodeLocked — even on a locked vault. This is
// correct security behaviour: the daemon does not reveal vault lock state to
// unauthenticated callers.
func TestEntryOps_LockSemantics(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("correct-horse")
	// initUnlocked mints a session and stores it in c.Session.
	initUnlocked(t, c, pw)
	// Seed one entry while unlocked, then re-lock.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "K", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("seed put: %v", err)
	}
	if err := c.Call(ipc.OpVaultLock, ipc.VaultLockReq{}, &ipc.VaultLockResp{}); err != nil {
		t.Fatalf("lock: %v", err)
	}
	// Clear the session so subsequent calls have no auth context.
	c.Session = nil

	// list MUST work while locked, and reveal the NAME (not the value).
	var lr ipc.ListResp
	if err := c.Call(ipc.OpList, ipc.ListReq{}, &lr); err != nil {
		t.Fatalf("list while locked = %v, want allowed (names are visible)", err)
	}
	found := false
	for _, s := range lr.Secrets {
		if s.Name == "K" {
			found = true
		}
	}
	if !found {
		t.Errorf("list while locked did not return seeded name K: %+v", lr.Secrets)
	}

	// Under NU-3, value-touching ops on a locked vault with no session return
	// auth_required (the auth gate fires before the lock check).
	mustAuthReq := func(op ipc.Op, req any) {
		t.Helper()
		err := c.Call(op, req, &struct{}{})
		var e *ipc.ErrResponse
		if !errors.As(err, &e) || e.Code != ipc.CodeAuthRequired {
			t.Errorf("%s while locked (no session): err=%v, want auth_required", op, err)
		}
	}
	mustAuthReq(ipc.OpGet, ipc.GetReq{Name: "K"}) // value read
	mustAuthReq(ipc.OpPut, ipc.PutReq{Name: "K2", Value: []byte("v")})
	mustAuthReq(ipc.OpDelete, ipc.DeleteReq{Name: "K"})
	mustAuthReq(ipc.OpRename, ipc.RenameReq{OldName: "K", NewName: "K3"})

	// After re-unlock (session captured), delete works.
	var unlockResp ipc.VaultUnlockResp
	tok, err := c.CallAndCaptureSession(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &unlockResp, nil)
	if err != nil {
		t.Fatalf("re-unlock: %v", err)
	}
	c.Session = tok
	if err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "K"}, &ipc.DeleteResp{}); err != nil {
		t.Errorf("delete after unlock = %v, want success", err)
	}
}
