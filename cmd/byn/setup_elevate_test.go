package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// A sudo that does not actually elevate — a policy mapping the command back to
// the same user, a broken wrapper — would otherwise have byn re-exec itself for
// ever. The guard turns an infinite loop into one honest error.
func TestElevateWithSudo_DoesNotLoop(t *testing.T) {
	t.Setenv(elevationGuard, "1")
	var out, errBuf bytes.Buffer
	if _, took := elevateWithSudo(nil, os.Stdin, &out, &errBuf); took {
		t.Error("re-elevated despite already being the product of an elevation")
	}
	if errBuf.Len() != 0 {
		t.Errorf("said something on the loop guard: %q", errBuf.String())
	}
}

// The prompt is explained before it appears. An unexplained password prompt is
// alarming, and teaches people to type their password at whatever asks.
func TestElevateWithSudo_SaysWhyBeforeAsking(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sudo"); err != nil {
		t.Skip("no sudo on this machine")
	}
	t.Setenv(elevationGuard, "")
	t.Setenv("PATH", "/nonexistent") // LookPath fails: no prompt, no takeover
	var out, errBuf bytes.Buffer
	if _, took := elevateWithSudo(nil, os.Stdin, &out, &errBuf); took {
		t.Error("claimed to take over with no sudo available")
	}
	if strings.Contains(errBuf.String(), "password") {
		t.Errorf("announced a prompt it could not make: %q", errBuf.String())
	}
}

// A caller with no terminal — a script, CI, a test — must not be handed a sudo
// prompt it cannot answer. This one is here because the change first shipped
// without it and hung a unit test for ninety-six seconds waiting for a
// fingerprint that was never coming.
func TestElevateWithSudo_NeedsATerminalToPromptOn(t *testing.T) {
	t.Setenv(elevationGuard, "")
	var out, errBuf bytes.Buffer
	if _, took := elevateWithSudo(nil, strings.NewReader(""), &out, &errBuf); took {
		t.Error("tried to prompt with no terminal to prompt on")
	}
	if errBuf.Len() != 0 {
		t.Errorf("announced an elevation it did not attempt: %q", errBuf.String())
	}

	// A pipe is a real *os.File and still not a terminal — the case a shell
	// pipeline produces.
	r, w, err := os.Pipe()
	if err != nil {
		t.Skip("no pipe")
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	if _, took := elevateWithSudo(nil, r, &out, &errBuf); took {
		t.Error("treated a pipe as a terminal")
	}
}
