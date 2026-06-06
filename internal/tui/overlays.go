// Modal overlays: SCOPE picker, CONFIRM-DELETE, HELP, AUDIT view.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// ---- SCOPE picker -------------------------------------------------------

func (m Model) renderScopePicker() string {
	if m.picker == nil {
		return ""
	}
	colW := 16
	colHeader := func(name string, active bool) string {
		var s string
		if active {
			s = m.styles.SectionHeader.Render(name)
		} else {
			s = m.styles.DetailLabel.Render(name)
		}
		return padRightLipgloss(s, colW)
	}

	renderCol := func(items []string, cur int, active bool) []string {
		out := make([]string, 0, len(items)+1)
		for i, it := range items {
			marker := "○ "
			if i == cur {
				marker = "● "
			}
			line := marker + it
			if i == cur && active {
				line = m.styles.RailSelected.Render(line)
			}
			out = append(out, padRightLipgloss(line, colW))
		}
		return out
	}

	headers := []string{
		colHeader("VAULT", m.picker.Column == 0),
		colHeader("PROJECT", m.picker.Column == 1),
		colHeader("ENV", m.picker.Column == 2),
	}
	vaults := renderCol(m.picker.Vaults, m.picker.VaultIdx, m.picker.Column == 0)
	projects := renderCol(m.picker.Projects, m.picker.ProjectIdx, m.picker.Column == 1)
	envs := renderCol(m.picker.Envs, m.picker.EnvIdx, m.picker.Column == 2)

	rows := []string{strings.Join(headers, "  ")}
	rows = append(rows, m.styles.Divider.Render(strings.Repeat("─", colW*3+4)))
	maxR := max3(len(vaults), len(projects), len(envs))
	for i := 0; i < maxR; i++ {
		var a, b, c string
		if i < len(vaults) {
			a = vaults[i]
		} else {
			a = strings.Repeat(" ", colW)
		}
		if i < len(projects) {
			b = projects[i]
		} else {
			b = strings.Repeat(" ", colW)
		}
		if i < len(envs) {
			c = envs[i]
		} else {
			c = strings.Repeat(" ", colW)
		}
		rows = append(rows, a+"  "+b+"  "+c)
	}
	rows = append(rows, "")
	rows = append(rows, m.styles.StatusHint.Render("↑↓ select  Tab next column  Enter apply  ESC cancel"))

	body := lipgloss.JoinVertical(lipgloss.Left, rows...)
	return m.styles.Modal.Render(m.styles.DetailTitle.Render("SCOPE PICKER") + "\n" + body)
}

func max3(a, b, c int) int {
	if a < b {
		a = b
	}
	if a < c {
		a = c
	}
	return a
}

// ---- CONFIRM-DELETE -----------------------------------------------------

func (m Model) renderConfirm() string {
	if m.confirm == nil {
		return ""
	}
	what := "entry"
	detail := fmt.Sprintf("Permanently remove from %s", m.scopeDisplay())
	if m.confirm.Scope {
		what = scopeKindLabel(m.confirm.Kind)
		detail = "Permanently remove this " + what + " and everything under it"
	}
	title := m.styles.ModeConfirm.Render(fmt.Sprintf("Delete %s %q?", what, m.confirm.Name))
	body := lipgloss.JoinVertical(lipgloss.Left,
		title,
		"",
		detail,
		"",
		m.styles.StatusHint.Render("[d] confirm   [ESC] cancel"),
	)
	return m.styles.Modal.Render(body)
}

// ---- HELP overlay -------------------------------------------------------

func (m Model) renderHelp() string {
	w := m.Width
	h := m.Layout.Content.H + m.Layout.TopBar.H

	lines := []string{
		m.styles.AppName.Render("byn — HELP"),
		"",
		m.styles.SectionHeader.Render("NAVIGATION"),
		"  j/k       move down/up",
		"  h/l       fold/unfold tree (or panes)",
		"  Tab       swap rail ↔ content",
		"  Enter     activate (open scope / open edit)",
		"  g g       first row",
		"  G         last row",
		"",
		m.styles.SectionHeader.Render("EDITING"),
		"  i         edit selected entry's value (resumes draft if present)",
		"  a         add new entry",
		"  r         rename: entry (content) or vault/project/env (rail)",
		"  d d       delete (with confirm): entry (content) or scope (rail)",
		"  R         reveal value (audited)",
		"  y         copy value to clipboard (audited)",
		"",
		m.styles.SectionHeader.Render("DRAFT / SAVE (vi-style; no auto-save)"),
		"  type      modifies draft, NOT daemon",
		"  Enter     inserts newline in value (does NOT save)",
		"  ESC       leave INSERT but KEEP the draft",
		"  :w        commit draft to daemon",
		"  :q        leave edit (refuses if draft is dirty)",
		"  :q!       discard draft without saving",
		"  :wq       commit + leave",
		"  [DRAFT: NAME]    chip in status line whenever a draft is pending",
		"  [*]        marker next to entry rows that have an unsaved draft",
		"",
		m.styles.SectionHeader.Render("VIM COMMANDS (on the draft buffer)"),
		"  u         undo last change in draft",
		"  Ctrl-R    redo",
		"  y         yank selected entry's value → system clipboard (audited)",
		"  p         paste system clipboard into draft at cursor",
		"  Ctrl-V    paste system clipboard while in INSERT mode",
		"  y (REVEAL) copy the currently-revealed value to clipboard",
		"",
		m.styles.SectionHeader.Render("SCOPE"),
		"  s         scope picker overlay",
		"  :env X    switch env",
		"  :project Y :vault Z",
		"",
		m.styles.SectionHeader.Render("INHERITANCE BADGES (non-default envs)"),
		"  " + m.styles.StatusInherited.Render("↓") + "       value comes from the default env",
		"  " + m.styles.StatusOverridden.Render("⤴") + "       this env overrides default's value",
		"  " + m.styles.StatusNew.Render("✦") + "       created in this env, not in default",
		"",
		m.styles.SectionHeader.Render("OTHER"),
		"  g a       audit log",
		"  :         command palette",
		"  /         search/filter entries",
		"  :q        quit",
		"  ?         this help",
	}
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

// ---- AUDIT view ---------------------------------------------------------

// auditCaller renders who ran an event for the audit views, e.g.
// "socket:byn(pid 9123 uid 501)←node" or "portal:byn(uid 501)".
func auditCaller(e ipc.AuditEvent) string {
	s := e.CallerSurface
	if s == "" {
		s = "-"
	}
	out := s
	if e.CallerComm != "" {
		out += ":" + e.CallerComm
	}
	if e.CallerPID != 0 || e.CallerUID != 0 {
		out += fmt.Sprintf("(pid %d uid %d)", e.CallerPID, e.CallerUID)
	}
	if e.CallerPComm != "" {
		out += "←" + e.CallerPComm
	}
	return out
}

// auditCallerShort is the compact caller for the narrow RECENT AUDIT
// preview: just surface[:comm].
func auditCallerShort(e ipc.AuditEvent) string {
	if e.CallerSurface == "" {
		return ""
	}
	if e.CallerComm != "" {
		return e.CallerSurface + ":" + e.CallerComm
	}
	return e.CallerSurface
}

func (m Model) renderAudit() string {
	w := m.Width
	h := m.Layout.Content.H + m.Layout.TopBar.H

	header := m.styles.AppName.Render("AUDIT") + "  " + m.styles.Breadcrumb.Render(vaultOrDefault(m.scope.Vault))
	lines := []string{header, ""}

	if len(m.audit) == 0 {
		lines = append(lines, m.styles.Placeholder.Render("(no events)"))
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

	// Newest first.
	events := append([]struct{}{}, make([]struct{}, len(m.audit))...)
	_ = events
	for i := len(m.audit) - 1; i >= 0; i-- {
		e := m.audit[i]
		t := time.Unix(0, e.TS).Format("2006-01-02 15:04:05")
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
		lines = append(lines, fmt.Sprintf("  %s  %-14s %-18s  %s  %s",
			t, e.Op, entry, outcome, m.styles.EntryMeta.Render(auditCaller(e))))
	}
	lines = append(lines, "")
	lines = append(lines, m.styles.StatusHint.Render(fmt.Sprintf("%d events · live ↻ · q quit", len(m.audit))))

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
