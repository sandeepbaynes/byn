// Detail pane: right sidebar, Large tier only.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func (m Model) renderDetail() string {
	d := m.Layout.Detail
	if !d.Visible() {
		return ""
	}
	w := d.W
	h := d.H

	lines := make([]string, 0, h)

	e := m.currentEntry()
	if e == nil && m.Mode != ModeReveal && m.Mode != ModeInsert {
		lines = append(lines, m.styles.DetailTitle.Render("DETAIL"))
		lines = append(lines, m.styles.Divider.Render(strings.Repeat("─", w)))
		lines = append(lines, m.styles.Placeholder.Render("(select an entry)"))
		return joinAndPad(lines, w, h)
	}

	// Title varies by mode.
	title := ""
	if e != nil {
		title = e.Name
	}
	if m.Mode == ModeReveal && m.reveal != nil {
		secs := int(time.Until(m.reveal.ExpiresAt).Seconds())
		if secs < 0 {
			secs = 0
		}
		title = fmt.Sprintf("%s  (revealed %ds)", m.reveal.Name, secs)
	}
	if m.Mode == ModeInsert && m.edit != nil {
		title = fmt.Sprintf("%s  (editing)", m.edit.Name)
	}
	lines = append(lines, m.styles.DetailTitle.Render(title))
	lines = append(lines, m.styles.Divider.Render(strings.Repeat("─", w)))

	// Metadata.
	if e != nil {
		lines = append(lines, kv(m.styles, " Created", e.CreatedAt.Format("2006-01-02 15:04")))
		lines = append(lines, kv(m.styles, " Updated", e.UpdatedAt.Format("2006-01-02 15:04")))
		lines = append(lines, kv(m.styles, " Source ", e.Source))
	}
	lines = append(lines, "")

	// Mode-specific block.
	switch m.Mode {
	case ModeInsert:
		if m.edit != nil {
			lines = append(lines, m.styles.DetailWarn.Render("⚠  UNSAVED CHANGES"))
			lines = append(lines, m.styles.Divider.Render(strings.Repeat("─", w)))
			lines = append(lines, m.styles.DetailLabel.Render(" :w   commit"))
			lines = append(lines, m.styles.DetailLabel.Render(" :q   discard"))
		}
	case ModeReveal:
		if m.reveal != nil {
			lines = append(lines, m.styles.DetailTitle.Render("AUDIT EVENT EMITTED"))
			lines = append(lines, m.styles.Divider.Render(strings.Repeat("─", w)))
			lines = append(lines, m.styles.AuditOK.Render(fmt.Sprintf(" get %s    ok", m.reveal.Name)))
		}
	}
	lines = append(lines, "")
	lines = append(lines, m.styles.DetailLabel.Render(" R reveal   y copy   e edit"))

	return joinAndPad(lines, w, h)
}

func kv(s Styles, label, value string) string {
	return s.DetailLabel.Render(label) + "  " + s.DetailValue.Render(value)
}

func joinAndPad(lines []string, w, h int) string {
	for len(lines) < h {
		lines = append(lines, "")
	}
	if len(lines) > h {
		lines = lines[:h]
	}
	for i, ln := range lines {
		lines[i] = padRightLipgloss(ln, w)
	}
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}
