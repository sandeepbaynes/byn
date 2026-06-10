package main

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestRunVaultRename_TwoArgs(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpVaultRename, ipc.VaultRenameResp{})
	if got := runVaultRename([]string{"acme", "brand"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
	calls := fd.callsFor(ipc.OpVaultRename)
	if len(calls) != 1 {
		t.Fatalf("got %d calls, want 1", len(calls))
	}
	var req ipc.VaultRenameReq
	requireUnmarshal(t, calls[0].Body, &req)
	if req.OldName != "acme" || req.NewName != "brand" {
		t.Errorf("got (%q→%q), want (acme→brand)", req.OldName, req.NewName)
	}
}

func TestRunVaultRename_LockedRetriesWithPassword(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpVaultRename, lockedThenOK(ipc.VaultRenameResp{}))
	withStdin(t, "s3cret")
	if got := runVaultRename([]string{"--password-stdin", "acme", "brand"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
	calls := fd.callsFor(ipc.OpVaultRename)
	if len(calls) != 2 {
		t.Fatalf("got %d calls, want 2 (locked then retry)", len(calls))
	}
	var req ipc.VaultRenameReq
	requireUnmarshal(t, calls[1].Body, &req)
	if string(req.Password) != "s3cret" {
		t.Errorf("retry password = %q, want s3cret", req.Password)
	}
}

func TestRunVaultRename_RefusesDefault(t *testing.T) {
	noDaemon(t)
	if got := runVaultRename([]string{"default", "other"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d, want exitErr", got)
	}
}

func TestRunVaultRename_NoSource(t *testing.T) {
	noDaemon(t)
	// One arg + empty --vault scope ⇒ no source name.
	if got := runVaultRename([]string{"brand"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d, want exitErr", got)
	}
}

func TestRunVaultRename_BadArgs(t *testing.T) {
	noDaemon(t)
	if got := runVaultRename(nil, cliScope{}); got != exitErr {
		t.Fatalf("got %d, want exitErr", got)
	}
}

// TestRunVaultRename_AuthRequiredRetries verifies the per_action_auth retry
// path: first call returns auth_required, retry with password succeeds.
func TestRunVaultRename_AuthRequiredRetries(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpVaultRename, authRequiredThenOK(ipc.VaultRenameResp{}))
	withStdin(t, "s3cret\n")
	if got := runVaultRename([]string{"--password-stdin", "acme", "brand"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
	calls := fd.callsFor(ipc.OpVaultRename)
	if len(calls) != 2 {
		t.Fatalf("got %d rename calls, want 2 (auth_required then retry)", len(calls))
	}
	var req ipc.VaultRenameReq
	requireUnmarshal(t, calls[1].Body, &req)
	if string(req.Password) != "s3cret" {
		t.Errorf("retry password = %q, want s3cret", req.Password)
	}
}
