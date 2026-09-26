// Detail pane: right sidebar, Large tier only.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/sandeepbaynes/byn/internal/ipc"
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
		switch m.entryStatus(*e) {
		case StatusOverridden:
			lines = append(lines, kv(m.styles, " Default", "overridden here"))
		case StatusSameAsDefault:
			lines = append(lines, kv(m.styles, " Default", "same value"))
		}
		if e.Notes > 0 {
			// The count, never the text. A note is encrypted and the detail
			// pane is drawn whether or not the vault is open; saying how many
			// there are is the most a listing may say.
			lines = append(lines, kv(m.styles, " Notes  ", fmt.Sprintf("%d  (n to read)", e.Notes)))
		}
	}
	lines = append(lines, "")

	// What this variable is for. Plaintext, so it is here whether or not the
	// vault is open — which is the point of the field.
	if e != nil && e.Description != "" {
		lines = append(lines, m.styles.DetailLabel.Render(" DESCRIPTION"))
		if src := descriptionSource(*e); src != "" {
			lines = append(lines, m.styles.DetailWarn.Render(" "+src))
		}
		for _, ln := range wrapPlain(e.Description, w-1) {
			lines = append(lines, m.styles.DetailValue.Render(" "+ln))
		}
		lines = append(lines, "")
	}

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
	lines = append(lines, m.styles.DetailLabel.Render(" R reveal   y copy   i edit   n notes"))

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

// descriptionSource labels a description a person did not write. Their own
// words in the vault get no label — that is the unremarkable case, and marking
// it would make the marks on the other two easy to stop seeing.
func descriptionSource(e ipc.SecretMeta) string {
	switch {
	case e.DescriptionSource == ".byn":
		return "from the trusted .byn"
	case e.DescriptionAuthor == "agent":
		if e.DescriptionComm != "" {
			return "written by " + e.DescriptionComm + ", not by you"
		}
		return "written by a process, not by you"
	default:
		return ""
	}
}

// wrapPlain breaks text to width on word boundaries. The detail pane is narrow
// and a description is a sentence, so a hard cut mid-word is the one thing that
// makes it unreadable.
func wrapPlain(text string, width int) []string {
	if width < 8 {
		width = 8
	}
	var out []string
	for _, para := range strings.Split(text, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		line := words[0]
		for _, w := range words[1:] {
			if len(line)+1+len(w) > width {
				out = append(out, line)
				line = w
				continue
			}
			line += " " + w
		}
		out = append(out, line)
	}
	return out
}
