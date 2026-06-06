// Render dispatch: builds the final terminal frame from the model.
//
// View() composes rail + content + detail + statusline into one
// lipgloss.Place'd string. Modal overlays (HELP, CONFIRM-DELETE,
// SCOPE picker) are rendered on top by replacing the content body.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// View is the bubbletea Model.View entrypoint. Composes rail +
// content + detail + status line, applying overlays (HELP, AUDIT,
// SCOPE picker, CONFIRM delete).
func (m Model) View() string {
	if m.Layout.Tier == TierBelowMin {
		return m.renderBelowMin()
	}

	// Overlays that take the whole screen.
	switch m.Mode {
	case ModeHelp:
		return m.composeOverlay(m.renderHelp())
	case ModeAudit:
		return m.composeOverlay(m.renderAudit())
	}

	// Compose rail | content | detail with status line at the bottom.
	rail := m.renderRail()
	content := m.renderContent()
	detail := m.renderDetail()
	body := joinHorizontal(rail, content, detail)

	// Overlay modals (centered) — SCOPE picker, CONFIRM-DELETE.
	if m.Mode == ModeScopePicker {
		body = overlayCenter(body, m.renderScopePicker(), m.Width, m.Layout.Content.H+m.Layout.TopBar.H)
	}
	if m.Mode == ModeConfirmDelete {
		body = overlayCenter(body, m.renderConfirm(), m.Width, m.Layout.Content.H+m.Layout.TopBar.H)
	}

	status := m.renderStatus()
	return lipgloss.JoinVertical(lipgloss.Left, body, status)
}

// ---- Helpers ------------------------------------------------------------

// joinHorizontal places the rail/content/detail blocks side by side
// with a 1-col gutter between adjacent visible panes. The gutter
// prevents the rightmost char of one pane from abutting the leftmost
// char of the next when both rows contain visible text.
func joinHorizontal(a, b, c string) string {
	gutter := func(lines int) string {
		if lines <= 0 {
			return ""
		}
		col := make([]string, lines)
		for i := range col {
			col[i] = " "
		}
		return strings.Join(col, "\n")
	}
	parts := []string{}
	visible := []string{a, b, c}
	visible = filterNonEmpty(visible)
	if len(visible) == 0 {
		return ""
	}
	rows := strings.Count(visible[0], "\n") + 1
	for i, p := range visible {
		if i > 0 {
			parts = append(parts, gutter(rows))
		}
		parts = append(parts, p)
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func filterNonEmpty(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// composeOverlay replaces content+rail+detail with a single full-width
// block (used by HELP and AUDIT). Status line stays.
func (m Model) composeOverlay(body string) string {
	status := m.renderStatus()
	return lipgloss.JoinVertical(lipgloss.Left, body, status)
}

// overlayCenter renders an overlay box centered over the existing body.
// Implementation: we lipgloss.Place the overlay over a same-sized
// frame. For v1 we just replace the visible content with a vertically
// stacked structure that puts the overlay at the visual center.
func overlayCenter(base, overlay string, width, height int) string {
	if overlay == "" {
		return base
	}
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, overlay)
}

// ---- Below-min ----------------------------------------------------------

func (m Model) renderBelowMin() string {
	msg := lipgloss.JoinVertical(lipgloss.Left,
		"",
		"  Terminal too small.",
		"  Resize to at least 40 × 12.",
		"",
		"  Or use:",
		"    $ byn list",
		"    $ byn get NAME",
		"",
		"  Press q to quit.",
		"",
	)
	if m.Width < 1 || m.Height < 1 {
		return msg
	}
	return lipgloss.Place(m.Width, m.Height, lipgloss.Center, lipgloss.Center, msg)
}

// ---- Status line --------------------------------------------------------

func (m Model) renderStatus() string {
	w := m.Width
	if w <= 0 {
		return ""
	}

	// COMMAND / SEARCH input takes the whole status line.
	if m.Mode == ModeCommand && m.cmdline != nil {
		line := m.cmdline.Prompt + " " + m.cmdline.Input + "█"
		return padRight(line, w)
	}
	if m.Mode == ModeSearch && m.cmdline != nil {
		line := m.cmdline.Prompt + " " + m.cmdline.Input + "█"
		return padRight(line, w)
	}

	modeLabel := m.modeBadge()
	context := m.statusContext()
	hints := m.statusHints()

	// Compose left/right halves. Left = "MODE  context". Right = hints.
	left := modeLabel + "  " + context
	if m.flashMsg != "" {
		left = modeLabel + "  " + m.flashMsg
	}
	// Persistent draft chip whenever a dirty edit is pending. The
	// chip is loud (red bold) so the user always knows they have
	// uncommitted work; clicking around won't make it lose state.
	if m.edit != nil && m.edit.Dirty() && m.Mode == ModeNormal {
		owner := m.edit.Name
		if m.edit.IsNew {
			owner = "(new)"
		}
		left += "  " + m.styles.Error.Render("[DRAFT: "+owner+"]")
	}
	// Persistent filter chip — added between context and hints
	// whenever a search filter is active so the user can never miss
	// it (the section header also calls it out, but the status line
	// is the constant).
	filterChip := ""
	if m.entriesFilter != "" && (m.Mode == ModeNormal || m.Mode == ModeInsert || m.Mode == ModeAdd) {
		filterChip = m.styles.DetailWarn.Render(
			fmt.Sprintf(" filter=%q ", m.entriesFilter))
	}
	gap := w - lipgloss.Width(left) - lipgloss.Width(filterChip) - lipgloss.Width(hints)
	if gap < 1 {
		gap = 1
	}
	mid := strings.Repeat(" ", gap/2)
	tail := strings.Repeat(" ", gap-gap/2)
	if filterChip == "" {
		return left + strings.Repeat(" ", gap) + hints
	}
	return left + mid + filterChip + tail + hints
}

func (m Model) modeBadge() string {
	switch m.Mode {
	case ModeNormal:
		return m.styles.ModeNormal.Render("NORMAL")
	case ModeInsert, ModeAdd:
		return m.styles.ModeInsert.Render("INSERT")
	case ModeRename, ModeScopeRename:
		return m.styles.ModeInsert.Render("RENAME")
	case ModeReveal:
		return m.styles.ModeReveal.Render("REVEALED")
	case ModeConfirmDelete:
		return m.styles.ModeConfirm.Render("CONFIRM")
	case ModeScopePicker:
		return m.styles.ModeScope.Render("SCOPE")
	case ModeAudit:
		return m.styles.ModeAudit.Render("AUDIT")
	case ModeHelp:
		return m.styles.ModeHelp.Render("HELP")
	}
	return m.Mode.String()
}

func (m Model) statusContext() string {
	switch m.Mode {
	case ModeReveal:
		if m.reveal != nil {
			secs := int(time.Until(m.reveal.ExpiresAt).Seconds())
			if secs < 0 {
				secs = 0
			}
			return fmt.Sprintf("%s  %ds", m.reveal.Name, secs)
		}
		return ""
	case ModeInsert, ModeAdd, ModeRename:
		if m.edit != nil {
			n := m.edit.Name
			if n == "" {
				n = "(new entry)"
			}
			size := len(m.edit.Value)
			return fmt.Sprintf("%s  %d/4096 B", n, size)
		}
	case ModeScopeRename:
		if m.scopeRename != nil {
			return "rename " + m.scopeRename.old
		}
	}
	return m.scopeDisplay() + "  " + m.lockedStatusChip()
}

func (m Model) lockedStatusChip() string {
	for _, v := range m.status.Vaults {
		if v.Name == vaultOrDefault(m.scope.Vault) {
			if v.Locked {
				return "locked"
			}
			return "unlocked"
		}
	}
	return ""
}

func (m Model) statusHints() string {
	switch m.Mode {
	case ModeNormal:
		focus := "rail"
		if m.Focus == FocusContent {
			focus = "entries"
		}
		return m.styles.StatusHint.Render(
			"[" + focus + "]  j/k nav  Tab swap  i edit  a add  : cmd  / search  ? help")
	case ModeInsert, ModeAdd, ModeRename:
		return m.styles.StatusHint.Render("ESC normal  :w save  :q cancel")
	case ModeScopeRename:
		return m.styles.StatusHint.Render("type new name  Enter rename  ESC cancel")
	case ModeReveal:
		return m.styles.StatusHint.Render("ESC hide  R extend  y copy  e edit")
	case ModeConfirmDelete:
		return m.styles.StatusHint.Render("d confirm  ESC cancel")
	case ModeScopePicker:
		return m.styles.StatusHint.Render("↑↓ pick  Tab col  Enter apply  ESC cancel")
	case ModeAudit:
		return m.styles.StatusHint.Render("q back  r refresh  / filter")
	case ModeHelp:
		return m.styles.StatusHint.Render("ESC close")
	}
	return ""
}

func padRight(s string, width int) string {
	w := lipgloss.Width(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}
