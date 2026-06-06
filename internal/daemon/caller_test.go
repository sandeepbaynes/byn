package daemon

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func findOp(events []ipc.AuditEvent, op string) *ipc.AuditEvent {
	for i := range events {
		if events[i].Op == op {
			return &events[i]
		}
	}
	return nil
}

// TestAudit_RecordsSocketCaller proves that an op driven over the Unix
// socket records the peer's UID, PID, process name, and surface=socket.
func TestAudit_RecordsSocketCaller(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("correct-horse")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "K", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 20}, &tail); err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	put := findOp(tail.Events, "put")
	if put == nil {
		t.Fatalf("no put event in audit tail: %+v", tail.Events)
	}
	if put.CallerSurface != "socket" {
		t.Errorf("caller_surface = %q, want socket", put.CallerSurface)
	}
	if put.CallerUID != uint32(os.Geteuid()) { //nolint:gosec // euid is non-negative
		t.Errorf("caller_uid = %d, want %d", put.CallerUID, os.Geteuid())
	}
	if put.CallerPID == 0 {
		t.Error("caller_pid is 0, want the peer PID")
	}
	if put.CallerComm == "" {
		t.Error("caller_comm is empty, want the peer process name")
	}
}

// TestAudit_RecordsPortalCaller proves an in-process Dispatch (the browser
// portal path) records surface=portal.
func TestAudit_RecordsPortalCaller(t *testing.T) {
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

	pw := []byte("pw")
	mustOK := func(op ipc.Op, body any) {
		t.Helper()
		req, err := ipc.NewRequest("t", op, body)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		if resp := d.Dispatch(ctx, req); resp.Err != nil {
			t.Fatalf("%s via Dispatch: %v", op, resp.Err)
		}
	}
	mustOK(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw})
	mustOK(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw})
	mustOK(ipc.OpPut, ipc.PutReq{Name: "K", Value: []byte("v")})

	req, _ := ipc.NewRequest("t", ipc.OpAuditTail, ipc.AuditTailReq{Lines: 20})
	resp := d.Dispatch(ctx, req)
	if resp.Err != nil {
		t.Fatalf("audit tail: %v", resp.Err)
	}
	var tail ipc.AuditTailResp
	if err := ipc.DecodeBody(ipc.BodyResp, resp, &tail); err != nil {
		t.Fatalf("decode tail: %v", err)
	}
	put := findOp(tail.Events, "put")
	if put == nil {
		t.Fatalf("no put event: %+v", tail.Events)
	}
	if put.CallerSurface != "portal" {
		t.Errorf("caller_surface = %q, want portal", put.CallerSurface)
	}
}
