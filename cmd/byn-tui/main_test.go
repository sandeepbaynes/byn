package main

import (
	"errors"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// TestReportCallError_DistinguishesUnreachableFromRefused.
//
// Before the editor moved out of byn it went through byn's own error handling,
// so a dead daemon produced "byn daemon is not running" and the command to fix
// it. Printing a raw error here would be a quiet regression for the most common
// failure there is.
//
// The exit codes matter as much as the words: a script cannot tell "start the
// daemon" from "the daemon said no" if both collapse to one status.
func TestReportCallError_DistinguishesUnreachableFromRefused(t *testing.T) {
	if got := reportCallError(ipc.ErrDaemonDown); got != exitUnreach {
		t.Errorf("a dead daemon should exit %d, got %d", exitUnreach, got)
	}
	refused := &ipc.ErrResponse{Code: ipc.CodeLocked, Message: "vault is locked", Recover: "byn unlock"}
	if got := reportCallError(refused); got != exitDaemonErr {
		t.Errorf("a daemon refusal should exit %d, got %d", exitDaemonErr, got)
	}
	if got := reportCallError(errors.New("something else")); got != exitErr {
		t.Errorf("an unclassified failure should exit %d, got %d", exitErr, got)
	}
}

// vaultStateByName is what decides whether the editor prompts for a password,
// so "absent" and "present but locked" must not blur.
func TestVaultStateByName(t *testing.T) {
	status := ipc.StatusResp{Vaults: []ipc.VaultSummary{
		{Name: "default", Locked: true},
		{Name: "work", Locked: false},
	}}
	if locked, exists := vaultStateByName(status, "default"); !exists || !locked {
		t.Errorf("default should exist and be locked, got exists=%v locked=%v", exists, locked)
	}
	if locked, exists := vaultStateByName(status, "work"); !exists || locked {
		t.Errorf("work should exist and be unlocked, got exists=%v locked=%v", exists, locked)
	}
	if _, exists := vaultStateByName(status, "nope"); exists {
		t.Error("an absent vault must not report as existing — the editor would try to " +
			"unlock something that is not there")
	}
}
