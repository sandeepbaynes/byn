package main

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestRunLock_All(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpVaultLock, ipc.VaultLockResp{Locked: 3})
	if got := runLock([]string{"--all"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
	calls := fd.callsFor(ipc.OpVaultLock)
	if len(calls) != 1 {
		t.Fatalf("got %d calls, want 1", len(calls))
	}
	var req ipc.VaultLockReq
	requireUnmarshal(t, calls[0].Body, &req)
	if req.Name != "*" {
		t.Errorf("Name = %q, want * (lock all)", req.Name)
	}
}
