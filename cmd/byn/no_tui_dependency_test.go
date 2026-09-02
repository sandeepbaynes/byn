package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestByn_DoesNotLinkTheTUIStack is the guard for a five-second startup tax.
//
// bubbletea's package init calls lipgloss.HasDarkBackground(), which asks the
// terminal for its background colour and waits up to five seconds for a reply.
// It is unconditional in v1 — the library calls it a workaround to be removed in
// v2, and there is no v2 — so EVERY command in a binary that merely links
// bubbletea pays it. On a terminal that answers, nothing is noticed; on a
// controlling terminal that does not (a pty with no emulator: `script`, serial
// consoles, CI runners that allocate a tty, some agent harnesses), `byn version`
// took 5.1 seconds. So did `byn status`, and `byn list`, and everything else.
//
// Go initialises imported packages before the importing one, so byn cannot
// pre-empt a dependency's init from its own code. Not linking it is the only way
// not to run it, which is why the editor is a separate binary.
//
// This asserts the dependency graph rather than a duration. A timing test would
// pass on any developer's machine, because their terminal answers the query —
// the tax is invisible exactly where it would be measured.
func TestByn_DoesNotLinkTheTUIStack(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}
	deps := string(out)
	for _, forbidden := range []string{
		"github.com/charmbracelet/bubbletea",
		"github.com/charmbracelet/lipgloss",
		"github.com/muesli/termenv",
	} {
		if strings.Contains(deps, forbidden) {
			t.Errorf("byn links %s again — every byn command now pays bubbletea's "+
				"terminal query at startup (5s where the terminal does not answer). "+
				"The editor belongs in cmd/byn-tui; byn launches it.", forbidden)
		}
	}
}

// And the other half: the editor must still link what it needs, or the split
// removed the feature rather than relocating it.
func TestBynTUI_StillLinksBubbletea(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "../byn-tui").Output()
	if err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}
	if !strings.Contains(string(out), "github.com/charmbracelet/bubbletea") {
		t.Fatal("byn-tui no longer links bubbletea — the editor cannot draw anything")
	}
}
