package main

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestRunVault_NoSub(t *testing.T) {
	if got := runVault(nil, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunVault_Unknown(t *testing.T) {
	if got := runVault([]string{"oops"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunVault_Help(t *testing.T) {
	for _, h := range []string{"help", "--help", "-h"} {
		if got := runVault([]string{h}, cliScope{}); got != exitOK {
			t.Fatalf("%q got %d", h, got)
		}
	}
}

func TestRunVaultList_Empty(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpVaultList, ipc.VaultListResp{Vaults: nil})
	if got := runVault([]string{"list"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunVaultList_JSON(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpVaultList, ipc.VaultListResp{Vaults: []ipc.VaultSummary{
		{Name: "default", Initialized: true, Locked: false},
		{Name: "acme", Initialized: true, Locked: true},
		{Name: "ghost", Initialized: false, Locked: true},
	}})
	if got := runVault([]string{"list", "--json"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunVaultList_Plain_AllStates(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpVaultList, ipc.VaultListResp{Vaults: []ipc.VaultSummary{
		{Name: "default", Initialized: true, Locked: false},
		{Name: "acme", Initialized: true, Locked: true},
		{Name: "ghost", Initialized: false},
	}})
	if got := runVault([]string{"list"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunVaultList_BadFlag(t *testing.T) {
	if got := runVault([]string{"list", "--zzz"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunVaultList_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runVault([]string{"list"}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

func TestRunVaultDelete_RefusesDefault(t *testing.T) {
	if got := runVault([]string{"delete", "default"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunVaultDelete_MissingName(t *testing.T) {
	if got := runVault([]string{"delete"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunVaultDelete_TooMany(t *testing.T) {
	if got := runVault([]string{"delete", "a", "b"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunVaultDelete_FromScope(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpVaultDelete, ipc.VaultDeleteResp{})
	if got := runVault([]string{"delete"}, cliScope{Vault: "acme"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunVaultDelete_OK(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpVaultDelete, ipc.VaultDeleteResp{})
	if got := runVault([]string{"delete", "acme"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunVaultDelete_DaemonError(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpVaultDelete, ipc.CodeVaultNotFound, "no such vault")
	if got := runVault([]string{"delete", "ghost"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}
