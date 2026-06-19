package daemon

import (
	"errors"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// TestAuditReseal_NoBreak_OverIPC: an intact chain returns NoBreak (nothing
// written), not an error. (The break→marker logic is unit-tested in
// internal/audit; the handler just forwards to the auditor.)
func TestAuditReseal_NoBreak_OverIPC(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte("p"))
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "k", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	var r ipc.AuditResealResp
	if err := c.Call(ipc.OpAuditReseal, ipc.AuditResealReq{Reason: "x"}, &r); err != nil {
		t.Fatalf("Reseal: %v", err)
	}
	if !r.NoBreak || r.BrokenIndex != -1 {
		t.Fatalf("intact chain: want NoBreak with BrokenIndex -1, got %+v", r)
	}
}

// TestAuditReseal_LockedVault_OverIPC: reseal is a deliberate owner action and
// must refuse a locked vault with CodeLocked.
func TestAuditReseal_LockedVault_OverIPC(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte("p"))
	if err := c.Call(ipc.OpVaultLock, ipc.VaultLockReq{}, &ipc.VaultLockResp{}); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	var r ipc.AuditResealResp
	err := c.Call(ipc.OpAuditReseal, ipc.AuditResealReq{Reason: "x"}, &r)
	var er *ipc.ErrResponse
	if !errors.As(err, &er) || er.Code != ipc.CodeLocked {
		t.Fatalf("reseal on locked vault: want CodeLocked, got %v", err)
	}
}

// TestAuditReseal_BadName_OverIPC: an invalid vault name is rejected with
// CodeBadName before any vault is opened.
func TestAuditReseal_BadName_OverIPC(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte("p"))
	var r ipc.AuditResealResp
	err := c.Call(ipc.OpAuditReseal, ipc.AuditResealReq{Vault: "bad/name", Reason: "x"}, &r)
	var er *ipc.ErrResponse
	if !errors.As(err, &er) || er.Code != ipc.CodeBadName {
		t.Fatalf("bad vault name: want CodeBadName, got %v", err)
	}
}
