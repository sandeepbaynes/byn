package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFindTUIBinary_PrefersTheOneBesideByn.
//
// Beside-first is what makes a `go install`-ed byn and a packaged one each find
// their own editor. Two byn installs of different versions on one machine is a
// situation `byn doctor` already reports; launching the older editor against the
// newer daemon because PATH happened to name it first would be a poor answer.
func TestFindTUIBinary_PrefersTheOneBesideByn(t *testing.T) {
	dir := t.TempDir()
	beside := filepath.Join(dir, tuiBinary)
	if err := os.WriteFile(beside, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A decoy earlier on PATH, which must lose.
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, tuiBinary), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", other)

	got, err := findTUIBinaryNear(filepath.Join(dir, "byn"))
	if err != nil {
		t.Fatalf("should have found the neighbour: %v", err)
	}
	if got != beside {
		t.Fatalf("found %q, want the one beside byn at %q", got, beside)
	}
}

// A non-executable file next to byn is not the editor. Picking it would produce
// a permission error at exec time instead of the actionable message below.
func TestFindTUIBinary_IgnoresANonExecutableNeighbour(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, tuiBinary), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := findTUIBinaryNear(filepath.Join(dir, "byn")); err == nil {
		t.Fatal("a non-executable neighbour must not be treated as the editor")
	}
}

// When it is genuinely absent the message has to say what is missing and that it
// is a separate binary — never a bare "exec: no such file", which sends someone
// looking for a bug in byn.
func TestFindTUIBinary_MissingSaysWhatIsWrong(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := findTUIBinaryNear(filepath.Join(t.TempDir(), "byn"))
	if err == nil {
		t.Fatal("expected an error when the editor is nowhere")
	}
	msg := err.Error()
	if !strings.Contains(msg, tuiBinary) {
		t.Errorf("the error must name the missing binary: %q", msg)
	}
	if !strings.Contains(msg, "separate binary") {
		t.Errorf("the error must explain that the editor ships separately, or it reads "+
			"as a broken install: %q", msg)
	}
}

// The scope the user asked THIS command for must reach the editor, or
// `byn --vault work edit` would open whatever BYN_VAULT says instead.
func TestTUIArgs_PassesTheResolvedScope(t *testing.T) {
	got := strings.Join(tuiArgs(cliScope{Vault: "work", Project: "api", Env: "stg"}), " ")
	for _, want := range []string{"--vault work", "--project api", "--env stg"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if len(tuiArgs(cliScope{})) != 0 {
		t.Error("an empty scope must pass no flags, so the editor applies its own defaults")
	}
}

// TestRunTUI_DoesNotExecWithoutATerminal is named after a failure that destroyed
// the test binary running it.
//
// runTUI performs a real execve, so once byn-tui was actually installed on the
// machine, a test that called runTUI had its own process replaced mid-run. The
// package failed with no failing test named, and only on a machine where byn had
// been installed — it passed everywhere byn-tui was absent, including where the
// change was developed.
//
// byn now refuses before exec'ing when there is no terminal, which is also the
// better behaviour: the editor takes over the terminal, so with none there is
// nothing to take over, and replacing this process with one that will refuse
// immediately makes the error arrive from a program the user never named.
func TestRunTUI_DoesNotExecWithoutATerminal(t *testing.T) {
	called := false
	orig := execTUI
	execTUI = func(string, []string, []string) error { called = true; return nil }
	t.Cleanup(func() { execTUI = orig })

	// go test gives the process pipes, not a terminal — the same condition as a
	// script, a pipeline, or CI.
	if got := runTUI(nil, cliScope{}); got != exitErr {
		t.Fatalf("runTUI without a terminal returned %d, want %d", got, exitErr)
	}
	if called {
		t.Fatal("runTUI exec'd the editor with no terminal to draw on; when this is a " +
			"real execve rather than a stub, it replaces the calling process")
	}
}

// The editor must be pinned to byn's own version, never @latest for a release.
// An editor from a different release is a mismatch nobody asked for, and byn
// already reports version skew between its own parts as a fault.
func TestTUIModuleRef_PinsAReleaseVersion(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })

	version = "0.6.4"
	if got := tuiModuleRef(); got != "github.com/sandeepbaynes/byn/cmd/byn-tui@v0.6.4" {
		t.Errorf("a release build must pin its own version, got %q", got)
	}
	version = "v0.6.4"
	if got := tuiModuleRef(); !strings.HasSuffix(got, "@v0.6.4") {
		t.Errorf("a leading v must not be doubled, got %q", got)
	}
	// A working-tree build names no published version; pinning it would fail
	// with a confusing "unknown revision" instead of installing anything.
	version = "0.6.4-2-gabc1234-dirty"
	if got := tuiModuleRef(); !strings.HasSuffix(got, "@latest") {
		t.Errorf("a development build must fall back to @latest, got %q", got)
	}
}
