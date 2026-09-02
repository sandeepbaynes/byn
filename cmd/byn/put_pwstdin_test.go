package main

import (
	"strings"
	"testing"
)

// TestPut_PasswordStdinWithNoValue_IsRefused.
//
// Reported from the macOS pass, and not macOS-specific: with --password-stdin
// the FIRST line of stdin is the password and the remainder is the value, so
//
//	printf 'my-secret' | byn put NAME --password-stdin
//
// sends the secret as the password and leaves nothing to store. Where the write
// needs no authorization — a new name, the common case for an agent — the daemon
// accepts it, byn exits 0, and a later get returns "". Nothing says the secret
// was not saved.
//
// Silent, successful and wrong is the worst shape a bug can take in a secrets
// manager, so this is refused rather than stored.
func TestPut_PasswordStdinWithNoValue_IsRefused(t *testing.T) {
	withStdin(t, "just-the-secret-no-newline")
	out := captureStderr(t, func() {
		if code := runPut([]string{"--password-stdin", "SOME_NAME"}, cliScope{}); code == exitOK {
			t.Fatal("storing nothing must not succeed")
		}
	})
	// The message has to teach the contract, not just refuse: whoever hit this
	// believes the flag means "read the password from stdin", which is half true.
	for _, want := range []string{"FIRST line", "password", "SOME_NAME"} {
		if !strings.Contains(out, want) {
			t.Errorf("the error must explain the stdin contract and name the entry; missing %q in:\n%s", want, out)
		}
	}
}

// The documented form still works: password on the first line, value after it.
// This is the shape scripts and CI use, and it must not be collateral damage.
func TestPut_PasswordStdinWithAValue_IsAccepted(t *testing.T) {
	withStdin(t, "the-master-password\nthe-actual-value")
	// Reaches the daemon call and fails there (no daemon in a unit test), which
	// is past the guard — that is what is being asserted.
	out := captureStderr(t, func() { _ = runPut([]string{"--password-stdin", "SOME_NAME"}, cliScope{}) })
	if strings.Contains(out, "consumed all of stdin") {
		t.Fatalf("a value WAS supplied after the password; the guard must not fire:\n%s", out)
	}
}

// An empty value remains storable on purpose — what is refused above is the
// flag-ordering mistake, not the idea of an empty secret.
func TestPut_EmptyValueWithoutTheFlag_IsStillAllowed(t *testing.T) {
	withStdin(t, "")
	out := captureStderr(t, func() { _ = runPut([]string{"DELIBERATE_EMPTY"}, cliScope{}) })
	if strings.Contains(out, "consumed all of stdin") {
		t.Fatalf("without --password-stdin an empty value is legitimate:\n%s", out)
	}
}
