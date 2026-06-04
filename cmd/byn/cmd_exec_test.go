package main

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestRunExec_NoSeparator(t *testing.T) {
	if got := runExec([]string{"echo", "hi"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunExec_EmptyChildArgv(t *testing.T) {
	if got := runExec([]string{"--"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunExec_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runExec([]string{"--", "echo", "hi"}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

func TestRunExec_ListErrors(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpList, ipc.CodeLocked, "locked")
	if got := runExec([]string{"--", "echo", "hi"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunExec_BinaryNotInPath(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{})
	// Use a child binary that is guaranteed not to exist.
	if got := runExec([]string{"--", "byn-no-such-binary-zzz"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunExec_GetErrors(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{{Name: "A"}}})
	fd.onErr(ipc.OpGet, ipc.CodeLocked, "locked")
	if got := runExec([]string{"--", "echo"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}
