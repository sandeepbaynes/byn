package main

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestRunPasswd_StdinTwoLines(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpVaultPasswd, ipc.VaultPasswdResp{})
	withStdin(t, "old-secret\nnew-passphrase\n")
	if got := runPasswd([]string{"--password-stdin"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
	calls := fd.callsFor(ipc.OpVaultPasswd)
	if len(calls) != 1 {
		t.Fatalf("got %d passwd calls, want 1", len(calls))
	}
	var req ipc.VaultPasswdReq
	requireUnmarshal(t, calls[0].Body, &req)
	if string(req.OldPassword) != "old-secret" {
		t.Errorf("old = %q, want old-secret", req.OldPassword)
	}
	if string(req.NewPassword) != "new-passphrase" {
		t.Errorf("new = %q, want new-passphrase", req.NewPassword)
	}
}

func TestRunPasswd_ShortNewRejected(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpVaultPasswd, ipc.VaultPasswdResp{})
	withStdin(t, "old-secret\nshort\n")
	if got := runPasswd([]string{"--password-stdin"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d, want exitErr (short new password)", got)
	}
	if n := len(fd.callsFor(ipc.OpVaultPasswd)); n != 0 {
		t.Errorf("short password reached the daemon: %d calls", n)
	}
}

func TestRunPasswd_StdinSingleLine(t *testing.T) {
	withStdin(t, "onlyoneline")
	if got := runPasswd([]string{"--password-stdin"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d, want exitErr (need two lines)", got)
	}
}

func TestRunPasswd_DaemonError(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpVaultPasswd, ipc.CodeWrongPassword, "current password is incorrect")
	withStdin(t, "wrong-old\nnew-passphrase\n")
	if got := runPasswd([]string{"--password-stdin"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d, want exitDaemonErr", got)
	}
}

func TestRunPasswd_BadFlag(t *testing.T) {
	if got := runPasswd([]string{"--zzz"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d, want exitErr", got)
	}
}

func TestReadTwoPasswordsStdin(t *testing.T) {
	withStdin(t, "alpha\nbravo\n")
	o, n, err := readTwoPasswordsStdin()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(o) != "alpha" || string(n) != "bravo" {
		t.Fatalf("got (%q,%q), want (alpha,bravo)", o, n)
	}
}
