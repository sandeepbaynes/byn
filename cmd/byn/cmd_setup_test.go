package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

func nonRoot() int { return 501 }

// TestRunSetup_RequiresRoot covers every form (provision, uninstall, purge):
// a non-root euid must fail with an actionable `sudo …` hint and never reach
// the orchestration (no real side effects in a test).
func TestRunSetup_RequiresRoot(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantHint string
	}{
		{"provision", nil, "sudo byn setup"},
		{"uninstall", []string{"--uninstall"}, "sudo byn setup --uninstall"},
		{"purge", []string{"--uninstall", "--purge"}, "sudo byn setup --uninstall --purge"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			rc := runSetupWith(tc.args, nonRoot, strings.NewReader(""), &out, &errBuf)
			if rc != exitErr {
				t.Errorf("rc = %d, want exitErr", rc)
			}
			if !strings.Contains(errBuf.String(), "must run as root") {
				t.Errorf("stderr = %q, want a root requirement message", errBuf.String())
			}
			if !strings.Contains(errBuf.String(), tc.wantHint) {
				t.Errorf("stderr = %q, want hint %q", errBuf.String(), tc.wantHint)
			}
		})
	}
}

func TestRunSetup_PurgeWithoutUninstallRejected(t *testing.T) {
	var out, errBuf bytes.Buffer
	// Even as root the combination is invalid; --purge alone makes no sense.
	rc := runSetupWith([]string{"--purge"}, func() int { return 0 }, strings.NewReader(""), &out, &errBuf)
	if rc != exitErr {
		t.Errorf("rc = %d, want exitErr", rc)
	}
	if !strings.Contains(errBuf.String(), "--purge is only valid with --uninstall") {
		t.Errorf("stderr = %q, want the --purge gating message", errBuf.String())
	}
}

func TestRunSetup_RejectsPositionalArgs(t *testing.T) {
	var out, errBuf bytes.Buffer
	rc := runSetupWith([]string{"extra"}, nonRoot, strings.NewReader(""), &out, &errBuf)
	if rc != exitErr {
		t.Errorf("rc = %d, want exitErr", rc)
	}
	if !strings.Contains(errBuf.String(), "takes no positional arguments") {
		t.Errorf("stderr = %q, want positional-args rejection", errBuf.String())
	}
}

func TestRunSetup_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	rc := runSetupWith([]string{"--nope"}, nonRoot, strings.NewReader(""), &out, &errBuf)
	if rc != exitErr {
		t.Errorf("rc = %d, want exitErr for an unknown flag", rc)
	}
}

func TestVerifyProvisioned(t *testing.T) {
	// Ownership is checked with uid/gid -1 so the (non-fatal) check is a no-op;
	// the load-bearing assertions are dir-exists + a correct owner record. The
	// -1 keeps this runnable off-root (the dir is owned by the test user, not
	// _byn) while still exercising the missing-dir / bad-record / wrong-uid
	// failure modes.
	t.Run("happy", func(t *testing.T) {
		dir := t.TempDir()
		rec := filepath.Join(dir, "owner")
		if err := privsep.WriteOwnerRecord(rec, 501); err != nil {
			t.Fatal(err)
		}
		if err := verifyProvisioned(dir, rec, 501, -1, -1); err != nil {
			t.Errorf("verifyProvisioned: %v", err)
		}
	})

	t.Run("missing dir", func(t *testing.T) {
		err := verifyProvisioned(filepath.Join(t.TempDir(), "nope"), "x", 501, -1, -1)
		if err == nil || !strings.Contains(err.Error(), "missing") {
			t.Errorf("err = %v, want a missing-dir error", err)
		}
	})

	t.Run("dir is a file", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "afile")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := verifyProvisioned(f, "x", 501, -1, -1)
		if err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Errorf("err = %v, want a not-a-directory error", err)
		}
	})

	t.Run("missing record", func(t *testing.T) {
		dir := t.TempDir()
		err := verifyProvisioned(dir, filepath.Join(dir, "owner"), 501, -1, -1)
		if err == nil || !strings.Contains(err.Error(), "owner record unreadable") {
			t.Errorf("err = %v, want an unreadable-record error", err)
		}
	})

	t.Run("wrong recorded uid", func(t *testing.T) {
		dir := t.TempDir()
		rec := filepath.Join(dir, "owner")
		if err := privsep.WriteOwnerRecord(rec, 999); err != nil {
			t.Fatal(err)
		}
		err := verifyProvisioned(dir, rec, 501, -1, -1)
		if err == nil || !strings.Contains(err.Error(), "expected 501") {
			t.Errorf("err = %v, want a UID-mismatch error", err)
		}
	})
}

func TestConfirmPurge(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"yes confirms", "yes\n", true},
		{"yes with spaces", "  yes  \n", true},
		{"y is not enough", "y\n", false},
		{"YES uppercase rejected", "YES\n", false},
		{"empty aborts", "\n", false},
		{"no aborts", "no\n", false},
		{"eof aborts", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			got := confirmPurge(strings.NewReader(tc.in), &out)
			if got != tc.want {
				t.Errorf("confirmPurge(%q) = %v, want %v", tc.in, got, tc.want)
			}
			if !strings.Contains(out.String(), "PERMANENTLY DELETE") {
				t.Errorf("confirmPurge did not print the danger banner: %q", out.String())
			}
		})
	}
}
