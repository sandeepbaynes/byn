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
	mustLocked(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "p"})
	mustLocked(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "e"})
	mustLocked(ipc.OpProjectDelete, ipc.ProjectDeleteReq{Name: "p"})
	mustLocked(ipc.OpEnvDelete, ipc.EnvDeleteReq{Project: "default", Name: "e"})
	mustLocked(ipc.OpProjectRename, ipc.ProjectRenameReq{OldName: "default", NewName: "x"})
	mustLocked(ipc.OpEnvRename, ipc.EnvRenameReq{Project: "default", OldName: "default", NewName: "x"})

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
// mutations (`put`/`delete`/`rename`) return CodeLocked.
func TestEntryOps_LockSemantics(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("correct-horse")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Seed one entry while unlocked, then re-lock.
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "K", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("seed put: %v", err)
	}
	if err := c.Call(ipc.OpVaultLock, ipc.VaultLockReq{}, &ipc.VaultLockResp{}); err != nil {
		t.Fatalf("lock: %v", err)
	}

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

	mustLocked := func(op ipc.Op, req any) {
		t.Helper()
		err := c.Call(op, req, &struct{}{})
		var e *ipc.ErrResponse
		if !errors.As(err, &e) || e.Code != ipc.CodeLocked {
			t.Errorf("%s while locked: err=%v, want CodeLocked", op, err)
		}
	}
	mustLocked(ipc.OpGet, ipc.GetReq{Name: "K"}) // value read
	mustLocked(ipc.OpPut, ipc.PutReq{Name: "K2", Value: []byte("v")})
	mustLocked(ipc.OpDelete, ipc.DeleteReq{Name: "K"})
	mustLocked(ipc.OpRename, ipc.RenameReq{OldName: "K", NewName: "K3"})

	// After unlock, delete works.
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("re-unlock: %v", err)
	}
	if err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "K"}, &ipc.DeleteResp{}); err != nil {
		t.Errorf("delete after unlock = %v, want success", err)
	}
}
