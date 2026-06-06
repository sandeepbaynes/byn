package main

import (
	"os"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// withStdin replaces os.Stdin with a pipe whose read end contains data.
// The pipe is closed after data is written, so io.ReadAll terminates.
func withStdin(t *testing.T, data string) {
	t.Helper()
	prev := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := w.WriteString(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = w.Close()
	os.Stdin = r
	t.Cleanup(func() {
		_ = r.Close()
		os.Stdin = prev
	})
}

func TestReadPasswordStdin_StripsNewline(t *testing.T) {
	withStdin(t, "secret\n")
	got, err := readPasswordStdin()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(got) != "secret" {
		t.Fatalf("got %q", got)
	}
}

func TestReadPasswordStdin_NoNewline(t *testing.T) {
	withStdin(t, "secret")
	got, err := readPasswordStdin()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(got) != "secret" {
		t.Fatalf("got %q", got)
	}
}

func TestReadPasswordStdin_Empty(t *testing.T) {
	withStdin(t, "")
	got, err := readPasswordStdin()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

func TestReadSecretValue_TerminalStdinRejected(t *testing.T) {
	// /dev/tty test would actually need a terminal. Instead point stdin
	// at a CharDevice-mimicking source: open /dev/null which is a
	// character device.
	prev := os.Stdin
	defer func() { os.Stdin = prev }()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()
	os.Stdin = f
	if _, err := readSecretValue(); err == nil {
		t.Fatal("expected terminal-rejection")
	}
}

func TestReadSecretValue_PipedOK(t *testing.T) {
	withStdin(t, "hello\n")
	got, err := readSecretValue()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestReadSecretValue_NoTrailingNewline(t *testing.T) {
	withStdin(t, "hello")
	got, err := readSecretValue()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
}

// ----- runInit / runUnlock / runLock -------------------------------------

func TestRunInit_PasswordStdin_ShortRejected(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpVaultInit, ipc.VaultInitResp{})
	withStdin(t, "short\n")
	if got := runInit([]string{"--password-stdin"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunInit_PasswordStdin_OK(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpVaultInit, ipc.VaultInitResp{})
	withStdin(t, "longenough-pw\n")
	if got := runInit([]string{"--password-stdin"}, cliScope{Vault: "acme"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
	var req ipc.VaultInitReq
	requireUnmarshal(t, fd.callsFor(ipc.OpVaultInit)[0].Body, &req)
	if req.Name != "acme" {
		t.Fatalf("name = %q", req.Name)
	}
}

func TestRunInit_BadFlag(t *testing.T) {
	if got := runInit([]string{"--what"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunInit_PromptModeNoTerminal(t *testing.T) {
	// Without --password-stdin, runInit calls auth.PromptStdin which
	// returns ErrNoTerminal in a test process. Exit code = exitErr.
	if got := runInit(nil, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunUnlock_PromptModeNoTerminal(t *testing.T) {
	if got := runUnlock(nil, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunInit_DaemonDown(t *testing.T) {
	noDaemon(t)
	withStdin(t, "longenough-pw\n")
	if got := runInit([]string{"--password-stdin"}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

func TestRunInit_DaemonError(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpVaultInit, ipc.CodeAlreadyInit, "already")
	withStdin(t, "longenough-pw\n")
	if got := runInit([]string{"--password-stdin"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunUnlock_PasswordStdin_OK(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpVaultUnlock, ipc.VaultUnlockResp{})
	withStdin(t, "pw\n")
	if got := runUnlock([]string{"--password-stdin"}, cliScope{Vault: "acme"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunUnlock_BadFlag(t *testing.T) {
	if got := runUnlock([]string{"--zz"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunUnlock_DaemonError(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpVaultUnlock, ipc.CodeWrongPassword, "nope")
	withStdin(t, "pw\n")
	if got := runUnlock([]string{"--password-stdin"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunLock_OK(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpVaultLock, ipc.VaultLockResp{Locked: 1})
	if got := runLock(nil, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunLock_BadFlag(t *testing.T) {
	if got := runLock([]string{"--no"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunLock_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runLock(nil, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

// ----- runPut / runGet / runList / runDelete / runRename -----------------

func TestRunPut_NoName(t *testing.T) {
	if got := runPut(nil, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunPut_ValueOnCLIRejected(t *testing.T) {
	if got := runPut([]string{"name", "value"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunPut_BadFlag(t *testing.T) {
	if got := runPut([]string{"--bogus"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunPut_StdinTerminalRejected(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpPut, ipc.PutResp{})
	prev := os.Stdin
	defer func() { os.Stdin = prev }()
	dn, _ := os.Open(os.DevNull)
	defer func() { _ = dn.Close() }()
	os.Stdin = dn
	if got := runPut([]string{"key"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunPut_OK(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpPut, ipc.PutResp{})
	withStdin(t, "the-value")
	if got := runPut([]string{"key"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
	var req ipc.PutReq
	requireUnmarshal(t, fd.callsFor(ipc.OpPut)[0].Body, &req)
	if req.Name != "key" || string(req.Value) != "the-value" {
		t.Fatalf("req=%+v value=%q", req, req.Value)
	}
}

func TestRunPut_CreateOnly(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpPut, ipc.PutResp{})
	withStdin(t, "v")
	if got := runPut([]string{"--create-only", "key"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
	var req ipc.PutReq
	requireUnmarshal(t, fd.callsFor(ipc.OpPut)[0].Body, &req)
	if !req.CreateOnly {
		t.Fatal("CreateOnly should be true")
	}
}

func TestRunPut_DaemonDown(t *testing.T) {
	noDaemon(t)
	withStdin(t, "v")
	if got := runPut([]string{"k"}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

func TestRunGet_NoName(t *testing.T) {
	if got := runGet(nil, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunGet_TooMany(t *testing.T) {
	if got := runGet([]string{"a", "b"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunGet_BadFlag(t *testing.T) {
	if got := runGet([]string{"--no"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunGet_OK(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpGet, ipc.GetResp{Name: "k", Value: []byte("v")})
	if got := runGet([]string{"k"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunGet_JSON(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpGet, ipc.GetResp{Name: "k", Value: []byte("v")})
	if got := runGet([]string{"--json", "k"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunGet_DaemonError(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpGet, ipc.CodeNotFound, "nope")
	if got := runGet([]string{"k"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunList_Empty(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: nil})
	if got := runList(nil, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunList_WithItems(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{{Name: "a"}, {Name: "b"}}})
	if got := runList(nil, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunList_JSON(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{{Name: "a"}}})
	if got := runList([]string{"--json"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunList_BadFlag(t *testing.T) {
	if got := runList([]string{"--zzz"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunList_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runList(nil, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

func TestRunDelete_NoName(t *testing.T) {
	if got := runDelete(nil, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunDelete_BadFlag(t *testing.T) {
	if got := runDelete([]string{"--zz"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunDelete_OK(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpDelete, ipc.DeleteResp{})
	if got := runDelete([]string{"k"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunRename_WrongArgs(t *testing.T) {
	if got := runRename([]string{"a"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunRename_BadFlag(t *testing.T) {
	if got := runRename([]string{"--no"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunRename_OK(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpRename, ipc.RenameResp{})
	if got := runRename([]string{"a", "b"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunRename_DaemonError(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpRename, ipc.CodeNotFound, "nope")
	if got := runRename([]string{"a", "b"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunRename_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runRename([]string{"a", "b"}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

func TestRunDelete_DaemonError(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpDelete, ipc.CodeNotFound, "nope")
	if got := runDelete([]string{"k"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunDelete_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runDelete([]string{"k"}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

func TestRunLock_DaemonError(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpVaultLock, ipc.CodeInternal, "boom")
	if got := runLock(nil, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunGet_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runGet([]string{"k"}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}
