package main

import (
	"os"
	"strings"
	"testing"
)

// TestRelease_ShipsTheEditorBinary guards a way to break `byn edit` for every
// user without breaking a single test.
//
// The editor lives in its own binary so that byn does not link bubbletea. byn
// resolves it beside itself at runtime, which means a release that builds byn
// and forgets byn-tui produces a byn whose editor simply is not there — and
// nothing in the code would notice, because the code is correct. Only the
// packaging is wrong.
func TestRelease_ShipsTheEditorBinary(t *testing.T) {
	cfg, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Skipf("release config unavailable: %v", err)
	}
	s := string(cfg)
	if !strings.Contains(s, "main: ./cmd/byn-tui") {
		t.Fatal("the release config no longer builds cmd/byn-tui — every published byn " +
			"would ship without its editor, and `byn edit` would fail at runtime")
	}
	if !strings.Contains(s, "binary: byn-tui") {
		t.Fatal("the byn-tui build does not name its output binary byn-tui, which is the " +
			"name byn looks for beside itself")
	}
}

// The Makefile is the other path a binary reaches a machine: `make install` for
// anyone building from source, which includes every developer of byn.
func TestMakefile_BuildsAndInstallsTheEditor(t *testing.T) {
	mk, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Skipf("Makefile unavailable: %v", err)
	}
	s := string(mk)
	if !strings.Contains(s, "./cmd/byn-tui") {
		t.Error("make build no longer builds the editor")
	}
	if !strings.Contains(s, "$(DESTDIR)$(LIBEXECDIR)/byn-tui") {
		t.Error("make install no longer installs the editor into libexec — a source build " +
			"would have a byn that cannot find it")
	}
}

// The curl installer is a third way a binary reaches a machine, and the one that
// already shipped a byn with no editor once: v0.6.3's archive carried byn-tui,
// the installer unpacked it into a temp directory and deleted it with the rest,
// and everyone who installed that way had `byn edit` fail. Nothing in the code
// was wrong; only the installer was.
func TestInstaller_PlacesTheEditorInLibexec(t *testing.T) {
	sh, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Skipf("install.sh unavailable: %v", err)
	}
	s := string(sh)
	if !strings.Contains(s, "byn-tui") {
		t.Fatal("install.sh no longer installs the editor; a curl|sh install would have " +
			"no `byn edit`")
	}
	if !strings.Contains(s, "/usr/local/libexec") {
		t.Error("install.sh must place the editor in byn's libexec directory, which is " +
			"where an installed byn looks for it first")
	}
}
