// Approvals overlay: the decision queue, inside the editor.
//
// It exists because the queue is where work stops. An agent blocked on consent
// stays blocked until a person answers, and until now the only way to answer was
// to leave the TUI for a terminal or a browser — so the tool somebody already has
// open was the one place that could not unblock them.
package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// approvalLabelWidth is the width of the label column, matching the terminal's
// card so the same facts sit in the same place in both surfaces.
const approvalLabelWidth = 8

// renderApprovals draws the queue.
func (m Model) renderApprovals(w, h int) string {
	var lines []string
	title := "APPROVALS — waiting on you"
	if m.approvalHistory {
		title = "APPROVALS — decided and expired"
	}
	lines = append(lines, m.styles.SectionHeader.Render(title), "")

	switch {
	case m.approvalsErr != nil:
		lines = append(lines, m.styles.AuditError.Render("could not read the queue: "+m.approvalsErr.Error()))
	case len(m.approvals) == 0:
		empty := "nothing waiting."
		if m.approvalHistory {
			empty = "nothing on record."
		}
		lines = append(lines, m.styles.EntryMeta.Render(empty))
	default:
		lines = append(lines, m.approvalLines(w)...)
	}

	lines = append(lines, "", m.approvalFooter())
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

// approvalLines renders every request, with the selected one marked.
func (m Model) approvalLines(w int) []string {
	var out []string
	for i, a := range m.approvals {
		marker := "  "
		if i == m.approvalCursor {
			marker = m.styles.StatusNew.Render("▸ ")
		}
		head := marker + m.styles.EntryName.Render(a.ID) + "  " + ellipsizeTUI(a.Subject, w-len(a.ID)-6)
		out = append(out, head)
		// Only the selected request is expanded. A queue of a dozen would
		// otherwise be a wall of six-line records, and the list is what you scan
		// to find the one you care about.
		if i != m.approvalCursor {
			continue
		}
		for _, line := range a.Summary {
			out = append(out, m.approvalField("runs", oneLineTUI(line, w-approvalLabelWidth-4)))
		}
		if a.AskOnce {
			out = append(out, m.approvalField("wants",
				m.styles.StatusOverridden.Render("a single use — approving grants one run")))
		}
		if a.Reason != "" {
			out = append(out, m.approvalField("why", a.Reason))
			out = append(out, m.approvalField("", m.styles.EntryMeta.Render("(said by whoever asked — byn cannot verify it)")))
		}
		if a.Requestor.Display != "" {
			out = append(out, m.approvalField("who", a.Requestor.Display))
		}
		if a.Status != "" && a.Status != "pending" {
			out = append(out, m.approvalField("outcome", m.approvalOutcome(a)))
			if a.DecidedReason != "" {
				out = append(out, m.approvalField("said", a.DecidedReason))
			}
		} else {
			out = append(out, m.approvalField("asked", approvalTiming(a)))
		}
		out = append(out, "")
	}
	return out
}

// approvalField renders one label/value row, right-aligning the label so every
// value starts in the same column.
func (m Model) approvalField(label, value string) string {
	pad := fmt.Sprintf("%*s", approvalLabelWidth, label)
	return "    " + m.styles.EntryMeta.Render(pad) + "  " + value
}

// approvalOutcome renders a decided status in a colour that means something:
// what happened and was allowed, what was refused, what lapsed with nobody
// deciding.
func (m Model) approvalOutcome(a ipc.ApprovalEntry) string {
	text := a.Status
	if a.Once {
		text += " (single use)"
	}
	if a.DecidedVia != "" {
		text += " via " + a.DecidedVia
	}
	switch a.Status {
	case "approved", "used":
		return m.styles.AuditOK.Render(text)
	case "denied", "revoked":
		return m.styles.AuditDenied.Render(text)
	default: // expired, cancelled
		return m.styles.EntryMeta.Render(text)
	}
}

// approvalTiming is the one field that is legitimately a list: age, deadline and
// retries all answer "when and how often".
func approvalTiming(a ipc.ApprovalEntry) string {
	parts := []string{compactAgeTUI(time.Since(time.Unix(a.CreatedAt, 0)))}
	if a.ExpiresAt > 0 {
		if left := time.Until(time.Unix(a.ExpiresAt, 0)); left > 0 {
			parts = append(parts, "expires in "+compactAgeTUI(left))
		} else {
			parts = append(parts, "expired")
		}
	}
	if a.Repeats > 0 {
		parts = append(parts, fmt.Sprintf("retried %d×", a.Repeats))
	}
	if a.Vault != "" {
		parts = append(parts, "vault "+a.Vault)
	}
	return strings.Join(parts, " · ")
}

// approvalFooter names the gestures available, including the reason line, which
// is otherwise invisible until somebody types into it.
func (m Model) approvalFooter() string {
	if m.approvalTyping {
		return m.styles.SectionHeader.Render("why: ") + m.approvalReason +
			m.styles.EntryMeta.Render("▏  (enter to keep, esc to clear — sent to whoever asked)")
	}
	keys := []string{
		"j/k move", "a approve", "o approve once", "d deny", "v revoke",
		"r reason", "h history", "esc close",
	}
	if m.approvalReason != "" {
		return m.styles.EntryMeta.Render(strings.Join(keys, " · ")) + "\n" +
			m.styles.EntryMeta.Render("   reason ready: ") + m.approvalReason
	}
	return m.styles.EntryMeta.Render(strings.Join(keys, " · "))
}

// selectedApproval returns the request under the cursor.
func (m Model) selectedApproval() (ipc.ApprovalEntry, bool) {
	if m.approvalCursor < 0 || m.approvalCursor >= len(m.approvals) {
		return ipc.ApprovalEntry{}, false
	}
	return m.approvals[m.approvalCursor], true
}

// compactAgeTUI renders a duration to one unit. "46h9m15s" is three facts where
// the reader wanted one.
func compactAgeTUI(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours())/24)
	}
}

func oneLineTUI(s string, limit int) string {
	return ellipsizeTUI(strings.Join(strings.Fields(s), " "), limit)
}

func ellipsizeTUI(s string, limit int) string {
	if limit < 8 {
		limit = 8
	}
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit-1]) + "…"
}

// keyApprovals handles input while the queue is open.
//
// The gestures mirror `byn approve`: a to grant, o for a single use, d to
// refuse, v to take a grant back. Approving asks for the master password
// because it hands out authority; denying and revoking do not, because they can
// only ever remove it — refusing has to stay the cheaper action or people learn
// to approve by reflex.
func (m Model) keyApprovals(msg tea.KeyMsg) (Model, tea.Cmd) {
	// The reason line owns the keyboard while it is open, or "d" would deny
	// instead of typing a d.
	if m.approvalTyping {
		switch msg.String() {
		case "esc":
			m.approvalTyping = false
			m.approvalReason = ""
			return m, nil
		case "enter":
			m.approvalTyping = false
			return m, nil
		case "backspace":
			if r := []rune(m.approvalReason); len(r) > 0 {
				m.approvalReason = string(r[:len(r)-1])
			}
			return m, nil
		default:
			if s := msg.String(); len([]rune(s)) == 1 {
				m.approvalReason += s
			}
			return m, nil
		}
	}

	switch msg.String() {
	case "esc", "q":
		m.Mode = ModeNormal
		m.approvalReason = ""
		return m, nil
	case "j", "down":
		if m.approvalCursor < len(m.approvals)-1 {
			m.approvalCursor++
		}
		return m, nil
	case "k", "up":
		if m.approvalCursor > 0 {
			m.approvalCursor--
		}
		return m, nil
	case "h":
		m.approvalHistory = !m.approvalHistory
		m.approvalCursor = 0
		return m, loadApprovalsCmd(m.client, m.approvalHistory)
	case "r":
		// Typed before deciding, so it is attached to whichever answer follows.
		m.approvalTyping = true
		return m, nil
	case "R":
		return m, loadApprovalsCmd(m.client, m.approvalHistory)
	case "d":
		a, ok := m.selectedApproval()
		if !ok || a.Status != "pending" {
			return m, nil
		}
		return m, decideApprovalCmd(m.client, a.ID, false, false, false, false, m.approvalReason, nil)
	case "v":
		a, ok := m.selectedApproval()
		if !ok || a.Status != "approved" {
			m.flash("only an approved request has a grant to take back", false)
			return m, nil
		}
		return m, decideApprovalCmd(m.client, a.ID, false, true, false, false, m.approvalReason, nil)
	case "a", "o":
		a, ok := m.selectedApproval()
		if !ok || a.Status != "pending" {
			return m, nil
		}
		// Approving grants authority, so it asks for the password exactly as the
		// terminal and the portal do. The pending decision is parked on the auth
		// overlay and replayed once the password is in.
		once := msg.String() == "o"
		m.pendingApproval = &pendingApproval{ID: a.ID, Once: once, Reason: m.approvalReason}
		m.Mode = ModeAuthRequired
		m.authReq = &authReqState{
			Cause:     "approving " + a.ID + " grants authority, so it needs the master password",
			kind:      authRetryApprove,
			priorMode: ModeApprovals,
		}
		return m, nil
	}
	return m, nil
}
