// Content pane: top bar (breadcrumb), ENV-VARS, FILES, RECENT AUDIT.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func (m Model) renderContent() string {
	w := m.Layout.Content.W
	h := m.Layout.Content.H + m.Layout.TopBar.H // include the top bar
	if w <= 0 {
		return ""
	}

	// Head (top bar + blank) and trailing sections (FILES / RECENT AUDIT)
	// are fixed-size chrome. Build them first so the ENV-VARS list can
	// take exactly the vertical space that remains and scroll within it,
	// rather than overflowing and pushing the trailing sections off the
	// bottom.
	head := []string{
		m.renderTopBar(w),
		"",
	}

	var tail []string
	if m.Layout.ShowFiles {
		tail = append(tail, "")
		tail = append(tail, m.renderFilesSection(w)...)
	}
	if m.Layout.AuditRows > 0 {
		tail = append(tail, "")
		tail = append(tail, m.renderAuditSection(w)...)
	}

	envBudget := h - len(head) - len(tail)
	if envBudget < 1 {
		envBudget = 1
	}

	lines := make([]string, 0, h)
	lines = append(lines, head...)
	lines = append(lines, m.renderEnvVarsSection(w, envBudget)...)
	lines = append(lines, tail...)

	// Some elements (the inline edit/reveal boxes) are multi-line strings
	// held as a single slice entry. Expand them into individual visual
	// rows so the pad/clip below bounds the REAL terminal height rather
	// than slice-element count — otherwise a 4-row reveal box counts as 1
	// and the frame overflows, pushing the status line off-screen.
	lines = flattenRows(lines)

	// Pad / clip to height.
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

func (m Model) renderTopBar(w int) string {
	var left string
	if m.Layout.Tier == TierTiny {
		left = m.styles.Breadcrumb.Render(m.scopeDisplayBreadcrumb())
	} else {
		left = m.styles.Breadcrumb.Render(strings.ReplaceAll(m.scopeDisplay(), "/", " / "))
	}
	right := m.lockedStatusChip()
	if right != "" {
		right = m.styles.StatusChip.Render(right)
	}
	gap := w - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

func (m Model) renderEnvVarsSection(w, budget int) []string {
	es := m.filteredEntries()
	var header string
	if m.entriesFilter != "" {
		// Make the active filter unmissable: count shows
		// `matching/total`, the filter string is highlighted, and an
		// inline clear hint (ESC) is on the same line.
		header = fmt.Sprintf("ENV-VARS  filter=%q  (%d of %d match — ESC to clear)",
			m.entriesFilter, len(es), len(m.entries))
	} else {
		header = fmt.Sprintf("ENV-VARS (%d)", len(es))
	}
	var headerLine string
	if m.entriesFilter != "" {
		headerLine = m.styles.DetailWarn.Render(header)
	} else {
		headerLine = m.styles.SectionHeader.Render(header)
	}
	action := m.styles.Action.Render("+ add (a)")
	gap := w - lipgloss.Width(headerLine) - lipgloss.Width(action)
	if gap < 1 {
		gap = 1
	}
	out := []string{
		headerLine + strings.Repeat(" ", gap) + action,
		m.styles.Divider.Render(strings.Repeat("─", w)),
	}
	// Per-env legend: explain the badge column when the active env is
	// not the project's default and at least one entry has a marker.
	if envOrDefault(m.scope.Env) != "default" && len(es) > 0 {
		legend := m.styles.StatusInherited.Render("↓ inherited") +
			"   " + m.styles.StatusOverridden.Render("⤴ overrides default") +
			"   " + m.styles.StatusNew.Render("✦ new in env")
		out = append(out, "   "+legend)
	}

	if len(es) == 0 && m.entriesFilter == "" {
		switch {
		case m.entriesErr != nil && m.isVaultLockedErr(m.entriesErr):
			out = append(out, m.styles.Error.Render("  Vault is locked"))
			out = append(out, m.styles.Placeholder.Render(
				"  Run `byn --vault "+vaultOrDefault(m.scope.Vault)+
					" unlock` from a shell, then return."))
		case m.entriesErr != nil:
			out = append(out, m.styles.Error.Render("  Error: "+m.entriesErr.Error()))
		default:
			out = append(out, m.styles.Placeholder.Render("  (no env-vars in this scope)"))
		}
		// Don't early-return — we still need to render the ADD-ENTRY
		// form below when m.Mode == ModeAdd, even if the visible
		// list is empty.
	}
	// Window the entry rows so the selected row stays visible — the list
	// scrolls like the rail instead of being clipped at the bottom.
	// rowsAvail is the space left under the header/divider/legend that
	// were just appended to out.
	rowsAvail := budget - len(out)
	if rowsAvail < 1 {
		rowsAvail = 1
	}
	// Reserve rows for the inline expanded box (REVEAL value / INSERT or
	// RENAME editor) so the box — and its hint line — stays on-screen even
	// when its entry is the last row of a long list.
	entryRows := rowsAvail - m.expandedBoxRows(w)
	if entryRows < 1 {
		entryRows = 1
	}
	start, end := entryWindow(len(es), m.entryCursor, entryRows)
	for i := start; i < end; i++ {
		e := es[i]
		selected := m.Focus == FocusContent && i == m.entryCursor && m.Mode == ModeNormal
		expanded := false
		// Show inline editor for INSERT or REVEAL on this row.
		if e.Name == m.editingName() {
			expanded = true
		}
		out = append(out, m.renderEntryRow(e, selected, expanded, w))
		if expanded && m.Mode == ModeInsert {
			out = append(out, m.renderEditBox(w))
		}
		if expanded && m.Mode == ModeRename {
			out = append(out, m.renderRenameBox(w))
		}
		if expanded && m.Mode == ModeReveal && m.reveal != nil {
			out = append(out, m.renderRevealBox(w))
		}
	}
	// ADD-ENTRY appears as a synthetic row at the bottom.
	if m.Mode == ModeAdd && m.edit != nil {
		out = append(out, m.renderEntryAddSynthetic(w))
		out = append(out, m.renderAddBoxes(w)...)
	}
	return out
}

// flattenRows expands any multi-line strings in the slice into individual
// single-row entries, so downstream height accounting (pad/clip) counts
// real terminal rows.
func flattenRows(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.IndexByte(s, '\n') >= 0 {
			out = append(out, strings.Split(s, "\n")...)
		} else {
			out = append(out, s)
		}
	}
	return out
}

// visualRows is the number of terminal rows a (possibly multi-line) string
// occupies. The empty string is one (blank) row.
func visualRows(s string) int {
	return strings.Count(s, "\n") + 1
}

// expandedBoxRows is the number of terminal rows the inline expanded box
// (REVEAL value / INSERT or RENAME editor) for the active entry occupies,
// or 0 when nothing is expanded.
func (m Model) expandedBoxRows(w int) int {
	switch m.Mode {
	case ModeReveal:
		if m.reveal != nil {
			return visualRows(m.renderRevealBox(w))
		}
	case ModeInsert:
		if m.edit != nil {
			return visualRows(m.renderEditBox(w))
		}
	case ModeRename:
		if m.edit != nil {
			return visualRows(m.renderRenameBox(w))
		}
	}
	return 0
}

// entryWindow returns the [start,end) slice of a length-n entry list that
// keeps cursor visible within rows visible rows. When the list fits, the
// whole range is returned. Otherwise the window slides so the cursor sits
// within it (pinned to the bottom edge once scrolled past the fold),
// mirroring the rail's scroll behavior.
func entryWindow(n, cursor, rows int) (int, int) {
	if rows >= n {
		return 0, n
	}
	start := 0
	if cursor >= rows {
		start = cursor - rows + 1
	}
	if maxStart := n - rows; start > maxStart {
		start = maxStart
	}
	if start < 0 {
		start = 0
	}
	end := start + rows
	if end > n {
		end = n
	}
	return start, end
}

// editingName returns the name of the entry being edited/revealed, "" otherwise.
func (m Model) editingName() string {
	switch m.Mode {
	case ModeInsert, ModeRename:
		if m.edit != nil {
			return m.edit.Name
		}
	case ModeReveal:
		if m.reveal != nil {
			return m.reveal.Name
		}
	}
	return ""
}

func (m Model) renderEntryRow(e ipc.SecretMeta, selected, expanded bool, w int) string {
	marker := "  "
	if expanded {
		marker = "▼ "
	} else if selected {
		marker = "▸ "
	}
	// Dirty-draft marker — shown when there's an unsaved edit on
	// THIS entry. Visible from NORMAL view so the user knows where
	// the pending change lives.
	dirtyMark := ""
	if m.edit != nil && m.edit.Dirty() && !m.edit.IsNew && m.edit.Name == e.Name {
		dirtyMark = m.styles.Error.Render("[*]") + " "
	}
	// Inheritance status badge (2 cells incl. trailing space). Hidden
	// when the active env IS default — there's nothing to compare against.
	badge := "  "
	switch m.entryStatus(e) {
	case StatusInherited:
		badge = m.styles.StatusInherited.Render("↓") + " "
	case StatusOverridden:
		badge = m.styles.StatusOverridden.Render("⤴") + " "
	case StatusNew:
		badge = m.styles.StatusNew.Render("✦") + " "
	}
	name := e.Name

	// Compose: marker + badge + name + masked + size + date
	// Columns auto-shrink by tier.
	maskWidth, sizeWidth, dateWidth := layoutColumnsForTier(m.Layout.Tier, w)
	size := fmt.Sprintf("%d B", 0) // unknown until fetched
	if e.UpdatedAt.IsZero() {
		size = ""
	}
	date := e.UpdatedAt.Format(m.Layout.DateFmt)
	mask := maskBar(maskWidth)
	cols := []string{
		marker + badge + dirtyMark + name,
	}
	if maskWidth > 0 {
		cols = append(cols, m.styles.EntryMasked.Render(mask))
	}
	if sizeWidth > 0 {
		// size unknown without get; we elide for now.
		_ = sizeWidth
		_ = size
	}
	if dateWidth > 0 {
		cols = append(cols, m.styles.EntryMeta.Render(date))
	}
	line := alignColumns(cols, w)
	if selected {
		return m.styles.EntrySelected.Render(line)
	}
	return line
}

func maskBar(width int) string {
	if width <= 0 {
		return ""
	}
	return strings.Repeat("●", width)
}

// layoutColumnsForTier returns (mask, size, date) widths.
func layoutColumnsForTier(t Tier, _ int) (int, int, int) {
	switch t {
	case TierTiny:
		// Just name + date.
		return 0, 0, 5
	case TierMedium:
		return 10, 0, 5
	case TierStandard:
		return 16, 8, 10
	case TierLarge:
		return 16, 8, 10
	}
	return 0, 0, 0
}

func alignColumns(cols []string, totalW int) string {
	if len(cols) == 0 {
		return ""
	}
	if len(cols) == 1 {
		return padRightLipgloss(cols[0], totalW)
	}
	left := cols[0]
	right := strings.Join(cols[1:], "  ")
	gap := totalW - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 2 {
		gap = 2
	}
	return left + strings.Repeat(" ", gap) + right
}

func (m Model) renderEditBox(w int) string {
	if m.edit == nil {
		return ""
	}
	inner := w - 6
	if inner < 12 {
		inner = 12
	}
	line := boxedLine("", m.edit.Value, true, m.edit.CursorIdx, inner)
	box := m.styles.EditBox.Render(line)
	return strings.Join(indentLines("   ", box), "\n")
}

func (m Model) renderRenameBox(w int) string {
	if m.edit == nil {
		return ""
	}
	inner := w - 6
	if inner < 12 {
		inner = 12
	}
	line := boxedLine("rename: ", m.edit.Value, true, m.edit.CursorIdx, inner)
	box := m.styles.EditBox.Render(line)
	return strings.Join(indentLines("   ", box), "\n")
}

func (m Model) renderRevealBox(w int) string {
	if m.reveal == nil {
		return ""
	}
	inner := w - 6
	if inner < 12 {
		inner = 12
	}
	line := boxedLine("", m.reveal.Value, false, 0, inner)
	box := m.styles.EditBox.Render(line)
	box = strings.Join(indentLines("   ", box), "\n")
	secs := int(time.Until(m.reveal.ExpiresAt).Seconds())
	if secs < 0 {
		secs = 0
	}
	hint := m.styles.Action.Render(fmt.Sprintf("⏱  hides in %ds   R extend   y copy   ESC hide", secs))
	return box + "\n   " + hint
}

func (m Model) renderEntryAddSynthetic(_ int) string {
	return "▼ (new entry)"
}

func (m Model) renderAddBoxes(w int) []string {
	if m.edit == nil {
		return nil
	}
	// Box budget. Lipgloss adds 2 cols for the rounded border (1 left
	// + 1 right), and we prefix every box line with 3 spaces of indent.
	// So contentW must leave: 3 (prefix) + 2 (border) + 1 (right margin)
	// = 6 cells of headroom relative to the pane width.
	inner := w - 6
	if inner < 12 {
		inner = 12
	}
	nameStr := boxedLine("NAME:  ", m.edit.Name, m.edit.OnNameField, m.edit.CursorIdx, inner)
	valueStr := boxedLine("VALUE: ", m.edit.Value, !m.edit.OnNameField && m.Mode == ModeAdd, m.edit.CursorIdx, inner)

	// NAME box: red border + label when NameError is set so the
	// duplicate (or other validation) is unmissable. The inline error
	// renders directly under the NAME box too — the status-line
	// flash alone is too easy to glance past.
	var nameBox string
	if m.edit.NameError != "" {
		nameBox = m.styles.ErrorBox.Render(nameStr)
	} else {
		nameBox = m.styles.EditBox.Render(nameStr)
	}
	valueBox := m.styles.EditBox.Render(valueStr)

	// lipgloss boxes are MULTI-LINE; `"   " + box` would only indent
	// the first line, leaving the side borders flush-left while the
	// top/bottom corner segments sit 3 cols to the right. Indent EVERY
	// line of the box so the rounded corners align with the verticals.
	indent := "   "
	out := indentLines(indent, nameBox)
	if m.edit.NameError != "" {
		out = append(out, indent+m.styles.Error.Render("✘ "+m.edit.NameError))
	}
	out = append(out, indentLines(indent, valueBox)...)
	out = append(out, indent+m.styles.Action.Render("Tab next field   :w save   :q cancel"))
	return out
}

// indentLines splits s on newlines and prefixes each non-empty line
// with `prefix`. Used to indent multi-line lipgloss outputs (boxes,
// modals) so their borders align consistently.
func indentLines(prefix, s string) []string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		out = append(out, prefix+ln)
	}
	return out
}

// boxedLine builds an inner string of exactly `inner` cells: a fixed
// label, then the value with the cursor inserted at the right spot if
// `withCursor` is set, padded right to fill. Letting lipgloss border
// wrap this fixed-width inner string sidesteps the border-corner gap
// bug — lipgloss can't pad-mismatch its own border math when content
// is already exactly the requested width.
func boxedLine(label, value string, withCursor bool, cursorIdx, inner int) string {
	v := value
	if withCursor {
		ci := cursorIdx
		if ci > len(v) {
			ci = len(v)
		}
		v = v[:ci] + "█" + v[ci:]
	}
	contentW := inner
	if contentW < 1 {
		contentW = 1
	}
	line := label + v
	// Visible-width pad to exactly contentW. lipgloss.Width understands
	// the cursor block + label correctly.
	gap := contentW - lipgloss.Width(line)
	if gap > 0 {
		line += strings.Repeat(" ", gap)
	} else if gap < 0 {
		// Truncate from the right of the value (keep label visible).
		over := -gap
		if len(value) >= over {
			v2 := value[:len(value)-over]
			if withCursor {
				ci := cursorIdx
				if ci > len(v2) {
					ci = len(v2)
				}
				v2 = v2[:ci] + "█" + v2[ci:]
			}
			line = label + v2
			gap = contentW - lipgloss.Width(line)
			if gap > 0 {
				line += strings.Repeat(" ", gap)
			}
		}
	}
	return line
}

func (m Model) renderFilesSection(w int) []string {
	header := m.styles.SectionHeader.Render("FILES (0)")
	action := m.styles.Action.Render("+ add (a)")
	gap := w - lipgloss.Width(header) - lipgloss.Width(action)
	if gap < 1 {
		gap = 1
	}
	return []string{
		header + strings.Repeat(" ", gap) + action,
		m.styles.Divider.Render(strings.Repeat("─", w)),
		m.styles.Placeholder.Render("  (none — Phase 5)"),
	}
}

func (m Model) renderAuditSection(w int) []string {
	header := m.styles.SectionHeader.Render("RECENT AUDIT")
	hint := m.styles.Action.Render("view all (ga)")
	gap := w - lipgloss.Width(header) - lipgloss.Width(hint)
	if gap < 1 {
		gap = 1
	}
	out := []string{
		header + strings.Repeat(" ", gap) + hint,
		m.styles.Divider.Render(strings.Repeat("─", w)),
	}
	if len(m.audit) == 0 {
		out = append(out, m.styles.Placeholder.Render("  (no events)"))
		return out
	}
	// Show last AuditRows events, newest first.
	n := m.Layout.AuditRows
	events := m.audit
	if n < len(events) {
		events = events[len(events)-n:]
	}
	// Reverse to newest-first.
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		t := time.Unix(0, e.TS).Format("15:04")
		entry := e.EntryName
		if entry == "" {
			entry = "-"
		}
		outcome := e.Outcome
		switch outcome {
		case "ok":
			outcome = m.styles.AuditOK.Render("ok")
		case "denied":
			outcome = m.styles.AuditDenied.Render("denied")
		case "error":
			outcome = m.styles.AuditError.Render("error")
		}
		line := fmt.Sprintf("  %s  %-12s %-16s  %s  %s",
			t, e.Op, entry, outcome, m.styles.EntryMeta.Render(auditCallerShort(e)))
		out = append(out, padRightLipgloss(truncate(line, w), w))
	}
	return out
}
