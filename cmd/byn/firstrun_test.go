package main

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// Creating a vault is a real side effect, and a script that names the wrong
// vault must get an error rather than a brand-new empty one it did not ask for.
// Nothing here may create anything without a person on the other end.
func TestOfferVaultInit_RefusesWithoutAPerson(t *testing.T) {
	// jsonMode is the agent contract: never prompt, never act on a guess.
	if offerVaultInit(&ipc.Client{}, "somevault", true) {
		t.Error("created a vault in --json mode, where byn must never prompt")
	}
	// Tests do not run with a terminal on stdin, so this also covers the
	// piped/redirected case an agent actually hits.
	if offerVaultInit(&ipc.Client{}, "somevault", false) {
		t.Error("created a vault with no terminal to ask a person at")
	}
}

func TestIsNotInitErr(t *testing.T) {
	if !isNotInitErr(&ipc.ErrResponse{Code: ipc.CodeNotInit}) {
		t.Error("not_init reply not recognized")
	}
	if isNotInitErr(&ipc.ErrResponse{Code: ipc.CodeLocked}) {
		t.Error("a locked vault is not a missing one — it must not trigger creation")
	}
	if isNotInitErr(nil) {
		t.Error("nil is not an error")
	}
}
