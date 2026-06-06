package main

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// lockedThenOK returns a stateful handler: the first call replies
// CodeLocked, every later call replies with okBody. It mirrors a locked
// vault that accepts a password-authorized retry.
func lockedThenOK(okBody any) func([]byte) (any, *ipc.ErrMsg) {
	first := true
	return func([]byte) (any, *ipc.ErrMsg) {
		if first {
			first = false
			return nil, &ipc.ErrMsg{Code: ipc.CodeLocked, Message: "vault is locked"}
		}
		return okBody, nil
	}
}

func TestRunDelete_UnlockedSendsNoPassword(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpDelete, ipc.DeleteResp{})
	if got := runDelete([]string{"API_KEY"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
	calls := fd.callsFor(ipc.OpDelete)
	if len(calls) != 1 {
		t.Fatalf("got %d delete calls, want 1", len(calls))
	}
	var req ipc.DeleteReq
	requireUnmarshal(t, calls[0].Body, &req)
	if len(req.Password) != 0 {
		t.Errorf("unlocked delete carried a password: %q", req.Password)
	}
}

func TestRunDelete_LockedRetriesWithPassword(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpDelete, lockedThenOK(ipc.DeleteResp{}))
	withStdin(t, "hunter2\n")
	if got := runDelete([]string{"--password-stdin", "API_KEY"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
	calls := fd.callsFor(ipc.OpDelete)
	if len(calls) != 2 {
		t.Fatalf("got %d delete calls, want 2 (locked then retry)", len(calls))
	}
	var req ipc.DeleteReq
	requireUnmarshal(t, calls[1].Body, &req)
	if string(req.Password) != "hunter2" {
		t.Errorf("retry password = %q, want hunter2", req.Password)
	}
}

func TestRunDelete_NonLockedErrorNotRetried(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpDelete, ipc.CodeNotFound, "secret not found")
	if got := runDelete([]string{"GHOST"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d, want exitDaemonErr", got)
	}
	if n := len(fd.callsFor(ipc.OpDelete)); n != 1 {
		t.Fatalf("non-locked error retried: %d calls, want 1", n)
	}
}

func TestRunProjectDelete_LockedRetriesWithPassword(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpProjectDelete, lockedThenOK(ipc.ProjectDeleteResp{}))
	withStdin(t, "s3cret")
	if got := runProjectDelete([]string{"--password-stdin", "svc"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
	calls := fd.callsFor(ipc.OpProjectDelete)
	if len(calls) != 2 {
		t.Fatalf("got %d calls, want 2", len(calls))
	}
	var req ipc.ProjectDeleteReq
	requireUnmarshal(t, calls[1].Body, &req)
	if string(req.Password) != "s3cret" {
		t.Errorf("retry password = %q, want s3cret", req.Password)
	}
}

func TestRunEnvDelete_LockedRetriesWithPassword(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpEnvDelete, lockedThenOK(ipc.EnvDeleteResp{}))
	withStdin(t, "s3cret")
	if got := runEnvDelete([]string{"--password-stdin", "stg"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
	calls := fd.callsFor(ipc.OpEnvDelete)
	if len(calls) != 2 {
		t.Fatalf("got %d calls, want 2", len(calls))
	}
	var req ipc.EnvDeleteReq
	requireUnmarshal(t, calls[1].Body, &req)
	if string(req.Password) != "s3cret" {
		t.Errorf("retry password = %q, want s3cret", req.Password)
	}
}

func TestRunVaultDelete_LockedRetriesWithPassword(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpVaultDelete, lockedThenOK(ipc.VaultDeleteResp{}))
	withStdin(t, "s3cret")
	if got := runVaultDelete([]string{"--password-stdin", "acme"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
	calls := fd.callsFor(ipc.OpVaultDelete)
	if len(calls) != 2 {
		t.Fatalf("got %d calls, want 2", len(calls))
	}
	var req ipc.VaultDeleteReq
	requireUnmarshal(t, calls[1].Body, &req)
	if string(req.Password) != "s3cret" {
		t.Errorf("retry password = %q, want s3cret", req.Password)
	}
}

func TestRunVaultDelete_RefusesDefaultClientSide(t *testing.T) {
	// No daemon needed: the refusal happens before any IPC call.
	noDaemon(t)
	if got := runVaultDelete([]string{"default"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d, want exitErr", got)
	}
}
