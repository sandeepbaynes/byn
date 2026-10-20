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
func renderPendingEntry(w io.Writer, e ipc.ApprovalEntry, now time.Time, width int) {
	marker := " "
	if e.HighRisk {
		marker = roleWarn("!")
	}
	_, _ = fmt.Fprintf(w, "%s %s  %s\n", marker, roleIdent(e.ID),
		ellipsize(tildeHome(e.Subject), maxInt(width-len(e.ID)-4, 20)))

	for _, line := range e.Summary {
		label, value := splitSummaryVerb(oneLine(line, 400))
		_, _ = fmt.Fprint(w, fieldRowsWrapped(label, value, width, nil))
	}

	// Where a yes reaches, and what it hands over. These two rows are the
	// answer to "what will this approval do", which the card used to leave
	// to be inferred from a path: the vault was in the timing line or
	// nowhere, the project and env were not on the card at all, and the
	// variables the command would receive were never said.
	_, _ = fmt.Fprint(w, fieldRow("scope", scopeField(e)))
	if gets := getsText(e); gets != "" {
		_, _ = fmt.Fprint(w, fieldRowsWrapped("gets", gets, width, nil))
	}
	if from := fromText(e); from != "" {
		_, _ = fmt.Fprint(w, fieldRowsWrapped("from", from, width, nil))
	}

	// How long a plain `byn approve <id>` lasts, on every card and directly
	// under what it hands over. It changes what approving DOES, so an approver
	// should learn it before deciding, not from the result afterwards.
	//
	// It used to be said only when the asker wanted a single run, which left
	// every other card looking the same whether a yes meant six hours, one
	// hour or standing trust — the one thing nobody should have to guess.
	if lasts := lastsText(e); lasts != "" {
		_, _ = fmt.Fprint(w, fieldRowsWrapped("lasts", lasts, width, nil))
	}

	// Why, in the asker's words, marked as the claim it is. byn cannot check a
	// stated purpose and does not pretend to.
	switch {
	case e.Reason != "":
		_, _ = fmt.Fprint(w, fieldRowsWrapped("why", e.Reason, width, nil))
		// Provenance on its own line rather than trailing the sentence. Glued
		// to the end it was the thing that made the reason row overflow, and it
		// qualifies the whole reason, not its last word.
		_, _ = fmt.Fprint(w, fieldRowsWrapped("", "(said by whoever asked — byn cannot verify it)", width, roleNote))
	default:
		_, _ = fmt.Fprint(w, fieldRowsWrapped("why", `not given — an agent can pass one with byn exec --reason "…"`, width, roleNote))
	}

	// Who asked, from the kernel rather than from the request. This is the half
	// byn can vouch for, and it answers "was that my agent or something else".
	if who := e.Requestor.Display; who != "" {
		_, _ = fmt.Fprint(w, fieldRowsWrapped("who", who, width, nil))
	}
	// Split out of "who". A path is a different kind of fact from an identity,
	// and gluing them with " in " made the longest line on the card out of the
	// two shortest facts on it.
	if e.Requestor.Cwd != "" {
		_, _ = fmt.Fprint(w, fieldRowsWrapped("where", tildeHome(e.Requestor.Cwd), width, nil))
	}
	// Not wrapped: the timing parts are already coloured, and it is the one
	// field built to stay short.
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
	if e.HighRisk {
		parts = append(parts, roleWarn("high risk"))
	}
	return strings.Join(parts, roleNote(" · "))
}

// scopeField renders vault · project · env, every field named even when it is
// the default: "default" is a vault like any other, and a card that omits it
// reads as if the question had no vault.
func scopeField(e ipc.ApprovalEntry) string {
	d := func(v string) string {
		if v == "" {
			return "default"
		}
		return v
	}
	return roleIdent("vault "+d(e.Vault)) + roleNote(" · ") + "project " + d(e.Project) +
		roleNote(" · ") + "env " + d(e.Env)
}

// getsText says what the command receives if approved, or "" for a kind whose
// summary already says (a widening names what it adds).
func getsText(e ipc.ApprovalEntry) string {
	switch {
	case e.GetsAll:
		return "every variable in the scope — the .byn allows *, including ones added later"
	case len(e.Gets) > 0:
		return strings.Join(e.Gets, ", ")
	case e.Kind == "action_unpinned":
		return roleNote("nothing — the .byn declares no env")
	case e.Kind == "adhoc":
		return roleNote("nothing")
	}
	return ""
}

// lastsText says how long a plain approval lasts: one run, a window after
// which the command asks again, or standing trust in a file. The asker's
// single-use request comes first because it replaces the window outright.
func lastsText(e ipc.ApprovalEntry) string {
	switch {
	case e.AskOnce:
		return roleWarn("one run") + roleNote(" — ") +
			"the asker wants a single use: spent on the first run, or lapsed unused after 30m; --always grants the usual window instead"
	case e.WindowSeconds > 0:
		return compactLeft(time.Duration(e.WindowSeconds)*time.Second) + roleNote(" — ") +
			"runs free for whoever asked, then asks again; --for 30m shortens it, --once makes it a single run"
	case e.Kind == "trust_widening":
		return "until the file changes again" + roleNote(" — ") +
			"standing trust in the .byn as it is now, not a window"
	}
	return ""
}

// fromText says what an ad hoc request is anchored to, since it has no .byn:
// the directory, and — flagged — a trusted file it is stepping around.
func fromText(e ipc.ApprovalEntry) string {
	if e.Kind != "adhoc" {
		return ""
	}
	if e.Beside != "" {
		return roleWarn("ad hoc, beside " + tildeHome(e.Beside) + " — which does not cover this and is not changed by approving")
	}
	return "ad hoc — no .byn; anchored to the directory it runs in"
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
	id, status, when, scope, command, why string
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
	idW, statusW, whenW, scopeW := len("ID"), len("STATUS"), len("ASKED"), len("SCOPE")
	for _, e := range entries {
		r := historyRow{
			id:     e.ID,
			status: e.Status,
			when:   compactAge(now.Sub(time.Unix(e.CreatedAt, 0))) + " ago",
			scope:  plainScope(e),
			why:    e.Reason,
		}
		if len(e.Summary) > 0 {
			_, r.command = splitSummaryVerb(oneLine(e.Summary[0], 400))
		}
		// Marked in the rows too. A history is read to answer "what did it ask
		// for, and what did I give it", and single-use is half of the answer.
		if e.AskOnce {
			r.command = "[once] " + r.command
		}
		if r.why == "" {
			r.why = "—"
		}
		rows = append(rows, r)
		idW, statusW, whenW = maxInt(idW, len(r.id)), maxInt(statusW, len(r.status)), maxInt(whenW, len(r.when))
		scopeW = maxInt(scopeW, len(r.scope))
	}
	// A scope column stays legible on a narrow terminal by being capped, not
	// dropped: a history that does not say which vault each row was for
	// cannot answer the question it is read for.
	scopeW = minInt(scopeW, 28)

	// What is left after the fixed columns, split between the two free-text
	// ones. Command gets the larger share: it is what was asked for, and the
	// reason is optional and often absent.
	rest := width - (idW + statusW + whenW + scopeW + 10)
	cmdW, whyW := maxInt(rest*2/3, 12), maxInt(rest/3, 8)

	_, _ = fmt.Fprintf(w, "%s\n", roleLabel(fmt.Sprintf("%-*s  %-*s  %-*s  %-*s  %-*s  %s",
		idW, "ID", statusW, "STATUS", whenW, "ASKED", scopeW, "SCOPE", cmdW, "COMMAND", "WHY")))
	for _, r := range rows {
		_, _ = fmt.Fprintf(w, "%-*s  %s  %-*s  %-*s  %-*s  %s\n",
			idW, roleIdent(r.id),
			padColored(statusColor(r.status), r.status, statusW),
			whenW, r.when,
			scopeW, ellipsize(r.scope, scopeW),
			cmdW, ellipsize(r.command, cmdW),
			roleNote(ellipsize(r.why, whyW)))
	}
}

// plainScope is vault/project/env uncoloured, for a table cell.
func plainScope(e ipc.ApprovalEntry) string {
	d := func(v string) string {
		if v == "" {
			return "default"
		}
		return v
	}
	return d(e.Vault) + "/" + d(e.Project) + "/" + d(e.Env)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
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

// wrapTo word-wraps text to width, indenting every line after the first by
// indent spaces so a wrapped value stays inside its column.
//
// Without it the terminal breaks the line itself, at whatever character happens
// to land on the last column — mid-word, mid-path, and hard against the left
// margin. That is what turned an 80-column view of this list into "the .byn is
// no/t changed" and "services/ap/i": the layout was fine and the text was
// simply too wide for it. A column that only holds on a wide terminal is not a
// column.
//
// Colour is applied by the caller, per line, because wrapping a string that
// already contains escape sequences would count them toward the width and break
// exactly what it is here to fix.
func wrapTo(text string, width, indent int) []string {
	words := strings.Fields(text)
	if len(words) == 0 || width <= indent+8 {
		return []string{text} // too narrow to wrap usefully; let it overflow honestly
	}
	pad := strings.Repeat(" ", indent)
	var out []string
	line := ""
	for _, w := range words {
		switch {
		case line == "":
			line = w
		case len([]rune(line))+1+len([]rune(w)) <= width-indent:
			line += " " + w
		default:
			out = append(out, line)
			line = w
		}
	}
	out = append(out, line)
	for i := 1; i < len(out); i++ {
		out[i] = pad + out[i]
	}
	return out
}

// fieldRowsWrapped is fieldRow for a value that may not fit: the first line
// carries the label, continuations line up under the value.
func fieldRowsWrapped(label, value string, width int, color func(string) string) string {
	var b strings.Builder
	for i, line := range wrapTo(value, width, fieldLabelWidth+2) {
		if color != nil {
			// Colour each line separately so the escape bytes never enter the
			// width arithmetic.
			trimmed := strings.TrimLeft(line, " ")
			line = line[:len(line)-len(trimmed)] + color(trimmed)
		}
		if i == 0 {
			b.WriteString(fieldRow(label, line))
			continue
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// printWrapped writes dim helper text wrapped to the terminal, preserving the
// leading indent of the text it is given.
//
// The footer was the worst of it: one line ran 110 characters against an
// 80-column terminal, so a sentence explaining that approving does not run
// anything broke as "the .byn is no / t changed". Help text that is unreadable
// on the width people actually use is not help.
//
// Goes to stderr with the rest of the guidance, so it gates on useColor rather
// than useColorStdout.
func printWrapped(w io.Writer, text string, indent int) {
	trimmed := strings.TrimLeft(text, " ")
	lead := len(text) - len(trimmed)
	for i, line := range wrapTo(trimmed, termWidthStdout(), indent) {
		if i == 0 {
			line = strings.Repeat(" ", lead) + line
		}
		_, _ = fmt.Fprintln(w, dim(line))
	}
}
