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

// A real file, not a symlink into wherever byn happened to be installed.
//
// The daemon runs as the _byn service user, which cannot read inside a user's
// home — a symlink from /usr/local/bin into ~/.local/bin made systemd fail at
// exec with "Permission denied" and the service never came up. What the service
// execs has to be a file the service user can read.
func TestCopyExecutable_InstallsARealFileAndReplacesWhatIsThere(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "byn-real")
	if err := os.WriteFile(src, []byte("first"), 0o755); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "bin", "byn")

	if err := copyExecutable(src, dest); err != nil {
		t.Fatalf("copy: %v", err)
	}
	fi, err := os.Lstat(dest)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("installed a symlink — the service user may not be able to follow it")
	}
	if got := readFile(t, dest); got != "first" {
		t.Errorf("dest content = %q, want the source's", got)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("mode %v is not executable", fi.Mode().Perm())
	}

	// Replacing an existing entry must work: setup is re-run on every upgrade.
	other := filepath.Join(dir, "byn-other")
	if err := os.WriteFile(other, []byte("second"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyExecutable(other, dest); err != nil {
		t.Fatalf("recopy: %v", err)
	}
	if got := readFile(t, dest); got != "second" {
		t.Errorf("after recopy dest content = %q, want the new source's", got)
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

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestEnsureOnSystemPath_TakesTheEditorAlong: `byn edit` resolves byn-tui beside
// the running byn, so a setup that copies byn alone into /usr/local/bin leaves a
// byn whose editor is not there — everything works except the one command that
// needs a second binary, and only for people who installed with `go install`.
func TestEnsureOnSystemPath_TakesTheEditorAlong(t *testing.T) {
	src, err := os.ReadFile("setup_path.go")
	if err != nil {
		t.Fatalf("read setup_path.go: %v", err)
	}
	if !strings.Contains(string(src), "tuiBinary") {
		t.Fatal("setup no longer copies the editor next to byn; a go install-ed byn " +
			"would have no byn-tui in the system bin dir")
	}
}

// TestInstallTUIHelper_RemovesTheStaleBinDirCopy.
//
// v0.6.3 installed the editor into the system bin dir. v0.6.4 moved it to
// libexec, which leaves upgraders with a copy on PATH that byn no longer uses
// and nothing ever updates — frozen at the version that installed it while byn
// moves on, and a shadow waiting for the day libexec is missing.
//
// Removed only AFTER the libexec copy is in place, so a failure there can never
// leave a machine with no editor at all.
func TestInstallTUIHelper_RemovesTheStaleBinDirCopy(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "byn-tui"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("setup_path.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if !strings.Contains(s, "os.Remove(stale)") {
		t.Fatal("setup no longer removes the superseded bin-dir copy; upgraders keep a " +
			"stale editor on PATH for ever")
	}
	// Order matters more than the removal: the remove must come after the copy.
	if strings.Index(s, "os.Remove(stale)") < strings.Index(s, "copyExecutable(src, tuiLibexecPath)") {
		t.Fatal("the stale copy is removed BEFORE the replacement is installed; a failure " +
			"in between would leave the machine with no editor")
	}
}
