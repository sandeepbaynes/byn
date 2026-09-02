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
