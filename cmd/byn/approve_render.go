package main

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// renderPendingEntry writes one waiting request as a two-column record.
//
// It was a paragraph of loose sentences before: "runs /bin/true" with the verb
// the same colour as the command, an unlabelled line of boilerplate, an
// unlabelled line about the reason, "who:" in one colour, and then a trailing
// comma-separated run of age, expiry, retries and vault with no label at all.
// Five lines, three different ways of naming a field, nothing sharing a left
// edge. Every value now sits in one column with its name beside it, and every
// name is the same colour, so the eye can go down the labels or down the values
// and the two never mix.
func renderPendingEntry(w io.Writer, e ipc.ApprovalEntry, now time.Time) {
	marker := " "
	if e.HighRisk {
		marker = roleWarn("!")
	}
	_, _ = fmt.Fprintf(w, "%s %s  %s\n", marker, roleIdent(e.ID), tildeHome(e.Subject))

	for _, line := range e.Summary {
		label, value := splitSummaryVerb(oneLine(line, 100))
		_, _ = fmt.Fprint(w, fieldRow(label, value))
	}

	// Why, in the asker's words, marked as the claim it is. byn cannot check a
	// stated purpose and does not pretend to.
	switch {
	case e.Reason != "":
		_, _ = fmt.Fprint(w, fieldRow("why", e.Reason+roleNote("  (said by whoever asked — byn cannot verify it)")))
	default:
		_, _ = fmt.Fprint(w, fieldRow("why", roleNote(`not given — an agent can pass one with byn exec --reason "…"`)))
	}

	// Who asked, from the kernel rather than from the request. This is the half
	// byn can vouch for, and it answers "was that my agent or something else".
	if who := e.Requestor.Display; who != "" {
		_, _ = fmt.Fprint(w, fieldRow("who", who))
	}
	// Split out of "who". A path is a different kind of fact from an identity,
	// and gluing them with " in " made the longest line on the card out of the
	// two shortest facts on it.
	if e.Requestor.Cwd != "" {
		_, _ = fmt.Fprint(w, fieldRow("where", tildeHome(e.Requestor.Cwd)))
	}
	_, _ = fmt.Fprint(w, fieldRow("asked", pendingTiming(e, now)))
}

// pendingTiming is the one field that is legitimately a list: age, deadline,
// retries and vault are all answers to "when and how often", and separating
// them into four rows would bury the three fields that matter under bookkeeping.
// Joined with a middle dot rather than commas so it does not read as prose.
func pendingTiming(e ipc.ApprovalEntry, now time.Time) string {
	parts := []string{compactAge(now.Sub(time.Unix(e.CreatedAt, 0))) + " ago"}
	// How long is LEFT, not only how long it has waited. A request raised at the
	// end of a day can expire before anyone looks at it, and "asked 5h ago" does
	// not say that you have an hour to answer.
	if e.ExpiresAt > 0 {
		if left := time.Until(time.Unix(e.ExpiresAt, 0)); left > 0 {
			parts = append(parts, "expires in "+compactLeft(left))
		} else {
			parts = append(parts, roleBad("expired"))
		}
	}
	if e.Repeats > 0 {
		parts = append(parts, fmt.Sprintf("retried %d×", e.Repeats))
	}
	// Whether anything is still listening. Two requests an hour apart look
	// identical on a list, and one may have a process sitting on it right now
	// while the other was abandoned before you sat down.
	if e.NeededBy > 0 {
		if left := time.Until(time.Unix(e.NeededBy, 0)); left > 0 {
			parts = append(parts, roleWarn("needed within "+compactLeft(left)))
		} else {
			parts = append(parts, roleNote("no longer waiting"))
		}
	}
	if e.Vault != "" && e.Vault != "default" {
		parts = append(parts, "vault "+e.Vault)
	}
	if e.HighRisk {
		parts = append(parts, roleWarn("high risk"))
	}
	return strings.Join(parts, roleNote(" · "))
}

// splitSummaryVerb lifts the leading verb of a stored summary into the label
// column, so "runs /bin/true" becomes a `runs` label beside the command.
//
// The summary text itself is never rewritten: it is what a request's
// fingerprint is computed from, so changing it would invalidate pending
// requests and live grants. This splits a copy for display only, and only on a
// verb byn is known to write — anything else keeps the whole line as the value
// under a neutral label, which is the safe direction to be wrong in.
func splitSummaryVerb(line string) (label, value string) {
	for _, verb := range []string{"runs", "grants", "adds", "removes"} {
		if rest, ok := strings.CutPrefix(line, verb+" "); ok {
			return verb, rest
		}
	}
	return "asks", line
}

// historyRow is one decided request, flattened to a single line.
type historyRow struct {
	id, status, when, command, why string
}

// renderHistoryTable prints decided requests as a real table, one row each.
//
// The pending list is a handful of records you read; the history is dozens you
// scan, and the same layout does not serve both. Forty-five requests as
// six-line records is four hundred lines to page through to answer "what did it
// ask for, and did I say yes" — the question the history exists for. As rows,
// that is forty-five lines and the answer is a column.
//
// Truncated to the terminal width by design: `--json` carries every field
// untruncated, and the footer says so.
func renderHistoryTable(w io.Writer, entries []ipc.ApprovalEntry, now time.Time, width int) {
	rows := make([]historyRow, 0, len(entries))
	idW, statusW, whenW := len("ID"), len("STATUS"), len("ASKED")
	for _, e := range entries {
		r := historyRow{
			id:     e.ID,
			status: e.Status,
			when:   compactAge(now.Sub(time.Unix(e.CreatedAt, 0))) + " ago",
			why:    e.Reason,
		}
		if len(e.Summary) > 0 {
			_, r.command = splitSummaryVerb(oneLine(e.Summary[0], 400))
		}
		if r.why == "" {
			r.why = "—"
		}
		rows = append(rows, r)
		idW, statusW, whenW = maxInt(idW, len(r.id)), maxInt(statusW, len(r.status)), maxInt(whenW, len(r.when))
	}

	// What is left after the fixed columns, split between the two free-text
	// ones. Command gets the larger share: it is what was asked for, and the
	// reason is optional and often absent.
	rest := width - (idW + statusW + whenW + 8)
	cmdW, whyW := maxInt(rest*2/3, 12), maxInt(rest/3, 8)

	_, _ = fmt.Fprintf(w, "%s\n", roleLabel(fmt.Sprintf("%-*s  %-*s  %-*s  %-*s  %s",
		idW, "ID", statusW, "STATUS", whenW, "ASKED", cmdW, "COMMAND", "WHY")))
	for _, r := range rows {
		_, _ = fmt.Fprintf(w, "%-*s  %s  %-*s  %-*s  %s\n",
			idW, roleIdent(r.id),
			padColored(statusColor(r.status), r.status, statusW),
			whenW, r.when,
			cmdW, ellipsize(r.command, cmdW),
			roleNote(ellipsize(r.why, whyW)))
	}
}

// statusColor maps an outcome to a role, so the colour of a status always says
// the same thing: green happened and was allowed, red was refused, yellow is
// still waiting on a person, dim lapsed with nobody deciding.
func statusColor(status string) func(string) string {
	switch status {
	case "approved", "used":
		return roleGood
	case "denied", "revoked":
		return roleBad
	case "pending":
		return roleWarn
	default: // expired, and anything a newer daemon invents
		return roleNote
	}
}

// padColored pads to width using the UNCOLOURED length. Padding a coloured
// string counts its escape bytes as visible characters and pulls every
// following column out of line — on a terminal only, never in a test that
// captures output with colour disabled.
func padColored(color func(string) string, s string, width int) string {
	return color(s) + strings.Repeat(" ", maxInt(0, width-len(s)))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// compactAge renders how long ago something happened, to ONE unit.
//
// Go's default gives "46h9m15s ago", which is three facts where the reader
// wanted one and a column whose width swings with the seconds digit. Nobody
// scanning a history cares that a request from two days back was made at nine
// minutes past. "2d ago" is the answer to the question actually being asked.
func compactAge(d time.Duration) string {
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

// compactLeft renders time REMAINING, to two units.
//
// The opposite trade from compactAge, for the opposite question. An age is
// context; a deadline is something you act on, and "expires in 5h" when it is
// really 5h32m throws away the half hour you were deciding whether you had.
func compactLeft(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		if m := int(d.Minutes()) % 60; m > 0 {
			return fmt.Sprintf("%dh%dm", int(d.Hours()), m)
		}
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		if h := int(d.Hours()) % 24; h > 0 {
			return fmt.Sprintf("%dd%dh", int(d.Hours())/24, h)
		}
		return fmt.Sprintf("%dd", int(d.Hours())/24)
	}
}
