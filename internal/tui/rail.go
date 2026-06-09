// Rail: left sidebar with vault > project > env tree.
package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (m Model) renderRail() string {
	r := m.Layout.Rail
	if !r.Visible() {
		return ""
	}
	width := r.W
	height := r.H

	lines := make([]string, 0, height)

	// Header row: "BYN" in bold cyan.
	lines = append(lines, m.styles.AppName.Render("BYN"))

	// Vertical scroll: keep cursor visible.
	if m.railCursor < m.railOffset {
		m.railOffset = m.railCursor
	}
	maxVisible := height - 2 // -1 for header, -1 for bottom padding row
	if m.railCursor >= m.railOffset+maxVisible {
		m.railOffset = m.railCursor - maxVisible + 1
	}
	if m.railOffset < 0 {
		m.railOffset = 0
	}

	for i := m.railOffset; i < len(m.railRows) && i-m.railOffset < maxVisible; i++ {
		node := m.railRows[i]
		focused := m.Focus == FocusRail && i == m.railCursor
		lines = append(lines, m.renderRailNode(node, focused, width))
	}

	// Pad to height.
	for len(lines) < height {
		lines = append(lines, "")
	}
	if len(lines) > height {
		lines = lines[:height]
	}

	// Version footer in the bottom row — the scroll math above reserves it
	// (maxVisible = height-2). Dim + right-aligned so it reads as a subtle
	// corner annotation rather than a tree item.
	if height > 1 {
		lines[height-1] = m.renderRailVersion(width)
	}

	// Pad each line to rail width so the rail/content border is straight.
	for i, ln := range lines {
		lines[i] = padRightLipgloss(ln, width)
	}

	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// renderRailVersion renders the byn version as a dim, right-aligned footer in
// the rail. It degrades gracefully on narrow rails (truncates) and renders
// empty when there is no version string or no room.
func (m Model) renderRailVersion(width int) string {
	v := strings.TrimSpace(m.version)
	if v == "" || width <= 0 {
		return ""
	}
	if v[0] >= '0' && v[0] <= '9' {
		v = "v" + v // 0.0.1 -> v0.0.1; leave non-numeric ("dev") as-is
	}
	if lipgloss.Width(v) > width {
		v = truncate(v, width)
	}
	pad := width - lipgloss.Width(v)
	if pad < 0 {
		pad = 0
	}
	return strings.Repeat(" ", pad) + m.styles.RailDim.Render(v)
}

func (m Model) renderRailNode(node railNode, focused bool, width int) string {
	indent := strings.Repeat("  ", node.Depth)
	marker := "  "
	switch node.Kind {
	case nodeVault, nodeProject:
		if node.IsExpanded {
			marker = m.styles.RailMarker.Render("▼ ")
		} else {
			marker = m.styles.RailMarker.Render("▶ ")
		}
	case nodeEnv:
		if node.IsCurrentScope {
			marker = "● "
		} else {
			marker = "○ "
		}
	case nodeNewVault:
		marker = ""
	}
	// Inline rename: draw the editable buffer (with a cursor) in place of
	// the label for the node being renamed.
	if m.Mode == ModeScopeRename && m.scopeRename.matches(node) {
		input := renderScopeRenameInput(m.scopeRename.buf, m.scopeRename.cur)
		return indent + marker + input
	}

	label := node.Label
	// Use lipgloss.Width — len() counts ANSI escape bytes in styled
	// strings like `marker`, so subtracting it leaves too little room
	// for the label and produces premature ellipsis ("def…").
	label = truncate(label, width-lipgloss.Width(indent)-lipgloss.Width(marker)-1)

	var styled string
	switch node.Kind {
	case nodeNewVault:
		styled = m.styles.RailDim.Render(label)
	case nodeEnv:
		if node.IsCurrentScope {
			styled = m.styles.RailSelected.Render(label)
		} else {
			styled = m.styles.RailUnselected.Render(label)
		}
	case nodeProject:
		if node.IsCurrentScope {
			styled = m.styles.RailNodeOpen.Render(label)
		} else {
			styled = m.styles.RailNode.Render(label)
		}
	case nodeVault:
		if node.IsCurrentScope {
			styled = m.styles.RailNodeOpen.Render(label)
		} else {
			styled = m.styles.RailNode.Render(label)
		}
	}
	line := indent + marker + styled
	if focused {
		// Reverse the whole row for cursor highlight.
		line = m.styles.EntrySelected.Render(padRightLipgloss(line, width))
	}
	return line
}

// renderScopeRenameInput renders the rename buffer with a thin bar cursor at
// the given rune position, using reverse video so it stands out in the rail.
func renderScopeRenameInput(buf []rune, cur int) string {
	cursor := lipgloss.NewStyle().Reverse(true)
	if cur < 0 {
		cur = 0
	}
	if cur > len(buf) {
		cur = len(buf)
	}
	before := string(buf[:cur])
	after := string(buf[cur:])
	at := " "
	if cur < len(buf) {
		at = string(buf[cur])
		after = string(buf[cur+1:])
	}
	return before + cursor.Render(at) + after
}

func truncate(s string, maxW int) string {
	if maxW < 0 {
		return ""
	}
	if lipgloss.Width(s) <= maxW {
		return s
	}
	if maxW <= 1 {
		return "…"
	}
	runes := []rune(s)
	for len(runes) > 0 && lipgloss.Width(string(runes)+"…") > maxW {
		runes = runes[:len(runes)-1]
	}
	return string(runes) + "…"
}

func padRightLipgloss(s string, width int) string {
	w := lipgloss.Width(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}
