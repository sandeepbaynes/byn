package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// TestAuditChainDetail covers the doctor audit-check formatter directly (a
// resealed chain is hard to build through the live daemon; the reseal+verify
// logic itself is unit-tested in internal/audit).
func TestAuditChainDetail(t *testing.T) {
	if sev, d := auditChainDetail("default", 5, 5, 0); sev != "fail" ||
		!strings.Contains(d, "broken at event #5") || !strings.Contains(d, "byn audit reseal default") {
		t.Errorf("broken: sev=%s detail=%q", sev, d)
	}
	if sev, d := auditChainDetail("default", -1, 10, 0); sev != "ok" || d != "10 events, chain intact" {
		t.Errorf("intact: sev=%s detail=%q", sev, d)
	}
	if _, d := auditChainDetail("default", -1, 10, 1); !strings.Contains(d, "(1 acknowledged reseal)") {
		t.Errorf("1 reseal (singular): %q", d)
	}
	if _, d := auditChainDetail("default", -1, 10, 2); !strings.Contains(d, "(2 acknowledged reseals)") {
		t.Errorf("2 reseals (plural): %q", d)
	}
}

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
