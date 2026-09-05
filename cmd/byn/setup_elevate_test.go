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
	if _, took := elevateWithSudo("setup", nil, os.Stdin, &out, &errBuf); took {
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
	if _, took := elevateWithSudo("setup", nil, os.Stdin, &out, &errBuf); took {
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
	if _, took := elevateWithSudo("setup", nil, strings.NewReader(""), &out, &errBuf); took {
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
	if _, took := elevateWithSudo("setup", nil, r, &out, &errBuf); took {
		t.Error("treated a pipe as a terminal")
	}
}

// The service commands ask for the password themselves — but only where there
// is somebody to ask, and only where root is actually needed. Every "no" here
// must be silent, because the root policy that follows prints the real message.
func TestElevateServiceCommand_OnlyWhenItCanAndMust(t *testing.T) {
	t.Setenv(elevationGuard, "")
	yes := func() bool { return true }
	no := func() bool { return false }
	noTTY := strings.NewReader("")
	for _, tc := range []struct {
		name        string
		cmd         string
		rest        []string
		euid        int
		provisioned func() bool
	}{
		{"already root", "restart", nil, 0, yes},
		{"not provisioned", "restart", nil, 1000, no},
		{"owner command", "get", []string{"X"}, 1000, yes},
		{"start never elevates", "start", nil, 1000, yes},
		{"daemon status is not a service command", "daemon", []string{"status"}, 1000, yes},
		{"no terminal to prompt on", "restart", nil, 1000, yes},
		{"no terminal, daemon alias", "daemon", []string{"restart"}, 1000, yes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			if _, took := elevateServiceCommand(tc.cmd, tc.rest, tc.euid, tc.provisioned, noTTY, &out, &errBuf); took {
				t.Error("took over")
			}
			if errBuf.Len() != 0 || out.Len() != 0 {
				t.Errorf("said something when declining: %q %q", errBuf.String(), out.String())
			}
		})
	}
}

// The provisioning lookup hits passwd. It must not run for a command that would
// never elevate, nor when no prompt could be made anyway.
func TestElevateServiceCommand_DoesNotLookUpProvisioningNeedlessly(t *testing.T) {
	t.Setenv(elevationGuard, "")
	asked := false
	spy := func() bool { asked = true; return true }
	var out, errBuf bytes.Buffer
	elevateServiceCommand("get", []string{"X"}, 1000, spy, os.Stdin, &out, &errBuf)
	if asked {
		t.Error("looked up provisioning for an owner command")
	}
	elevateServiceCommand("restart", nil, 1000, spy, strings.NewReader(""), &out, &errBuf)
	if asked {
		t.Error("looked up provisioning with no terminal to prompt on")
	}
}

// The guard that stops setup from re-electing itself for ever covers the
// service commands too: a byn that is already the product of an elevation and
// still is not root must stop, not try again.
func TestElevateServiceCommand_DoesNotLoop(t *testing.T) {
	t.Setenv(elevationGuard, "1")
	var out, errBuf bytes.Buffer
	if _, took := elevateServiceCommand("restart", nil, 1000, func() bool { return true }, os.Stdin, &out, &errBuf); took {
		t.Error("re-elevated despite already being the product of an elevation")
	}
	if errBuf.Len() != 0 {
		t.Errorf("said something on the loop guard: %q", errBuf.String())
	}
}
