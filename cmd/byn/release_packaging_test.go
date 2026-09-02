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
	if !strings.Contains(s, "$(DESTDIR)$(BINDIR)/byn-tui") {
		t.Error("make install no longer installs the editor — a source build would have " +
			"a byn that cannot find it")
	}
}
