package main

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestDefaultVaultState_NotPresent(t *testing.T) {
	st := ipc.StatusResp{Vaults: []ipc.VaultSummary{{Name: "acme"}}}
	locked, exists := defaultVaultState(st)
	if exists {
		t.Fatal("expected !exists")
	}
	if locked {
		t.Fatal("expected !locked")
	}
}

func TestDefaultVaultState_Present(t *testing.T) {
	st := ipc.StatusResp{Vaults: []ipc.VaultSummary{
		{Name: "acme", Locked: false},
		{Name: "default", Locked: true},
	}}
	locked, exists := defaultVaultState(st)
	if !exists {
		t.Fatal("expected exists")
	}
	if !locked {
		t.Fatal("expected locked")
	}
}

func TestDefaultVaultState_Empty(t *testing.T) {
	_, exists := defaultVaultState(ipc.StatusResp{})
	if exists {
		t.Fatal("empty list = not exist")
	}
}

func TestRunTUI_NotATerminal(t *testing.T) {
	// stdin/stdout in test are not terminals, so runTUI should exit
	// with exitErr immediately.
	if got := runTUI(nil, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunTUI_BadFlag(t *testing.T) {
	if got := runTUI([]string{"--bogus"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}
