package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInSystemBinDir(t *testing.T) {
	for path, want := range map[string]bool{
		"/usr/local/bin/byn":            true,
		"/usr/bin/byn":                  true,
		"/opt/homebrew/bin/byn":         true,
		"/home/someone/go/bin/byn":      false,
		"/home/someone/.local/bin/byn":  false,
		"/tmp/byn":                      false,
		"/usr/local/bin/nested/dir/byn": false,
	} {
		if got := inSystemBinDir(path); got != want {
			t.Errorf("inSystemBinDir(%q) = %v, want %v", path, got, want)
		}
	}
}

// A symlink is preferred so a later `go install ...@latest` is picked up
// without re-running setup — a copy would silently pin the version setup saw.
func TestLinkOrCopy_PrefersASymlinkAndReplacesWhatIsThere(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "byn-real")
	if err := os.WriteFile(src, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "bin", "byn")

	if err := linkOrCopy(src, dest); err != nil {
		t.Fatalf("link: %v", err)
	}
	got, err := filepath.EvalSymlinks(dest)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != src {
		t.Errorf("dest resolves to %q, want %q", got, src)
	}

	// Replacing an existing entry must work: setup is re-run on every upgrade.
	other := filepath.Join(dir, "byn-other")
	if err := os.WriteFile(other, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := linkOrCopy(other, dest); err != nil {
		t.Fatalf("relink: %v", err)
	}
	got, _ = filepath.EvalSymlinks(dest)
	if got != other {
		t.Errorf("after relink dest resolves to %q, want %q", got, other)
	}
}

// The hint has to name the actual problem and a command that fixes it: the
// failure it exists for is "byn: command not found", where the user cannot run
// byn to ask byn what went wrong.
func TestPathHint_NamesTheFixWhenNotOnPath(t *testing.T) {
	t.Setenv("PATH", "/usr/bin:/bin")
	hint := pathHint()
	exe, _ := os.Executable()
	if inSystemBinDir(exe) {
		if hint != "" {
			t.Errorf("a binary in a system dir should need no hint, got %q", hint)
		}
		return
	}
	if hint == "" {
		t.Fatal("no hint for a binary that is not on PATH")
	}
	if !strings.Contains(hint, "export PATH=") || !strings.Contains(hint, "setup") {
		t.Errorf("hint does not name a fix: %q", hint)
	}
}

// On PATH for this shell is good enough; do not nag.
func TestPathHint_SilentWhenReachable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("no executable path")
	}
	t.Setenv("PATH", filepath.Dir(exe))
	if hint := pathHint(); hint != "" {
		t.Errorf("hint given for a byn already on PATH: %q", hint)
	}
}
