// Package tui is the bubbletea+lipgloss TUI for byn.
//
// Entry point: Run(client, scope, version).
//
// See docs/tui-design.md for the full spec.
package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// Run launches the TUI program. Blocks until the user quits.
// version is shown in the "BYN" header (currently just used by the
// status line context where useful).
func Run(client Client, scope ipc.Scope, version string) error {
	model := NewModel(client, version, scope)
	// WithMouseAllMotion is intentionally omitted: on macOS Terminal.app
	// and iTerm2 it intercepts arrow keys and Tab as mouse-tracking
	// sequences, leaving the TUI input-dead. We're keyboard-only by
	// design — see docs/tui-design.md.
	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("tui: %w", err)
	}
	return nil
}
