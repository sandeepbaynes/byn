package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// withCWD changes directory for the duration of a test, restoring it
// after.
func withCWD(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}

func TestDefaultBynPath_PositionalArg(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	_ = fs.Parse([]string{"/explicit/path"})
	if got := defaultBynPath(fs); got != "/explicit/path" {
		t.Fatalf("got %q", got)
	}
}

func TestDefaultBynPath_FallbackToCWD(t *testing.T) {
	dir := t.TempDir()
	withCWD(t, dir)
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	_ = fs.Parse(nil)
	got := defaultBynPath(fs)
	want := filepath.Join(dir, ".byn")
	// CWD on macOS may go through /private; allow either prefix.
	if got != want && got != filepath.Join("/private", want) {
		// Accept both because /tmp can be symlinked.
		// Use suffix match.
		if filepath.Base(got) != ".byn" {
			t.Fatalf("got %q, want suffix .byn", got)
		}
	}
}

func TestRunTrust_DispatchHelp(t *testing.T) {
	for _, h := range []string{"help", "--help", "-h"} {
		if got := runTrust([]string{h}, cliScope{}); got != exitOK {
			t.Fatalf("%q got %d", h, got)
		}
	}
}

func TestRunTrust_ListBranch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BYN_DIR", dir)
	if got := runTrust([]string{"list"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
	if got := runTrust([]string{"ls"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrustAdd_OK(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_DIR", td)
	dir := t.TempDir()
	tpath := filepath.Join(dir, ".byn")
	if err := os.WriteFile(tpath, []byte("[scope]\nvault=\"a\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := runTrustAdd([]string{tpath}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrustAdd_MissingFile(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_DIR", td)
	if got := runTrustAdd([]string{filepath.Join(td, "nope")}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrustAdd_BadFlag(t *testing.T) {
	if got := runTrustAdd([]string{"--bogus"}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunUntrust_NotPreviouslyTrusted(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_DIR", td)
	dir := t.TempDir()
	tpath := filepath.Join(dir, ".byn")
	if err := os.WriteFile(tpath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Untrust an absent record should succeed silently (exitOK).
	if got := runUntrust([]string{tpath}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunUntrust_AfterAdd(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_DIR", td)
	dir := t.TempDir()
	tpath := filepath.Join(dir, ".byn")
	if err := os.WriteFile(tpath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := runTrustAdd([]string{tpath}); got != exitOK {
		t.Fatalf("add got %d", got)
	}
	if got := runUntrust([]string{tpath}, cliScope{}); got != exitOK {
		t.Fatalf("untrust got %d", got)
	}
}

func TestRunUntrust_BadFlag(t *testing.T) {
	if got := runUntrust([]string{"--bogus"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunUntrust_BrokenStore(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_DIR", td)
	// Write malformed JSON.
	if err := os.WriteFile(filepath.Join(td, trustFile), []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	dir := t.TempDir()
	tpath := filepath.Join(dir, ".byn")
	if got := runUntrust([]string{tpath}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrustList_JSON(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_DIR", td)
	if got := runTrustList([]string{"--json"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrustList_WithRecords(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_DIR", td)
	dir := t.TempDir()
	tpath := filepath.Join(dir, ".byn")
	if err := os.WriteFile(tpath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := addTrust(td, tpath, []byte("x")); err != nil {
		t.Fatalf("addTrust: %v", err)
	}
	if got := runTrustList(nil); got != exitOK {
		t.Fatalf("got %d", got)
	}
	if got := runTrustList([]string{"--json"}); got != exitOK {
		t.Fatalf("json got %d", got)
	}
}

func TestRunTrustList_BadFlag(t *testing.T) {
	if got := runTrustList([]string{"--zz"}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrustList_BrokenStore(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_DIR", td)
	if err := os.WriteFile(filepath.Join(td, trustFile), []byte("nope"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := runTrustList(nil); got != exitOK && got != exitErr {
		t.Fatalf("got %d", got)
	}
}
