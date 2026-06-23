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

// ---- AUTH REQUIRED overlay ----------------------------------------------

// renderAuthRequired renders the "Authorize" password overlay shown when the
// daemon returns CodeAuthRequired. The password is masked (replaced with
// bullets). Any retry error is shown in red beneath the input so the user can
// correct their password without leaving the overlay.
func (m Model) renderAuthRequired() string {
	if m.authReq == nil {
		return ""
	}
	ar := m.authReq

	// Title row.
	title := m.styles.ModeConfirm.Render("Authorize")

	// Subtitle: render the daemon's cause message. This is already
	// human-readable (e.g. the daemon's auth gate message or the
	// .byn [auth] policy message).
	cause := ar.Cause
	if cause == "" {
		cause = "vault requires password confirmation"
	}
	subtitle := m.styles.DetailLabel.Render(cause)

	// Password field: maskedInput (bullet per rune).
	masked := strings.Repeat("•", len(ar.buf))
	if len(ar.buf) == 0 {
		masked = m.styles.Placeholder.Render("(enter password)")
	}
	pwLabel := m.styles.SectionHeader.Render("Password: ") + masked + "█"

	// Retry error (wrong password etc.) shown in red.
	errLine := ""
	if ar.retryErr != "" {
		errLine = m.styles.Error.Render("✘ " + ar.retryErr)
	}

	rows := []string{
		title,
		"",
		subtitle,
		"",
		pwLabel,
	}
	if errLine != "" {
		rows = append(rows, "", errLine)
	}
	rows = append(rows, "", m.styles.StatusHint.Render("Enter submit  ESC cancel"))

	body := lipgloss.JoinVertical(lipgloss.Left, rows...)
	return m.styles.Modal.Render(body)
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

// auditMatches reports whether an event matches a free-text filter term
// (case-insensitive substring across every human-meaningful field).
func auditMatches(e ipc.AuditEvent, term string) bool {
	term = strings.ToLower(term)
	hay := strings.ToLower(strings.Join([]string{
		e.Op, e.Outcome, e.EntryName, e.Command, e.BynPath,
		e.Project, e.Env, e.CallerComm, e.CallerSurface,
		fmt.Sprintf("uid=%d", e.CallerUID),
	}, " "))
	return strings.Contains(hay, term)
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

	// Apply the active filter (client-side, matches any field).
	evs := m.audit
	if m.auditFilter != "" {
		filtered := make([]ipc.AuditEvent, 0, len(m.audit))
		for _, e := range m.audit {
			if auditMatches(e, m.auditFilter) {
				filtered = append(filtered, e)
			}
		}
		evs = filtered
	}
	// Newest first.
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
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
		lines = append(lines, fmt.Sprintf("  #%-6d %s  %-14s %-18s  %s  %s",
			e.Index, t, e.Op, entry, outcome, m.styles.EntryMeta.Render(auditCaller(e))))
	}
	if m.auditFilter != "" && len(evs) == 0 {
		lines = append(lines, m.styles.Placeholder.Render("  (no events match /"+m.auditFilter+")"))
	}
	lines = append(lines, "")
	keys := "] older · [ live · / filter · q quit"
	hint := fmt.Sprintf("%d events · live · %s", len(m.audit), keys)
	if m.auditBefore != 0 {
		hint = fmt.Sprintf("%d events · frozen below #%d · %s", len(m.audit), m.auditBefore, keys)
	}
	if m.auditFilter != "" {
		hint = fmt.Sprintf("%d/%d match /%s · esc clears · %s", len(evs), len(m.audit), m.auditFilter, keys)
	}
	lines = append(lines, m.styles.StatusHint.Render(hint))

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
