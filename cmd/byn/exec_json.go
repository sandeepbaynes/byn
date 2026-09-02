package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// Machine-readable output for `byn exec`.
//
// `--json` is documented globally as "agent mode: machine output", and exec is
// the command agents run most — but it was the one place the flag did nothing.
// A paused command printed its approval id inside an English sentence, so the
// only way to get the id was to pattern-match prose, which breaks the first
// time the wording is improved. The facts now travel as data.
//
// Prose still goes to stderr, unchanged, so a person watching a terminal sees
// what they always saw and stdout stays parseable.

// numericDetailKeys are detail fields that must be emitted as JSON numbers, so
// the same field has the same type whichever command produced it.
var numericDetailKeys = map[string]bool{"expires_at": true, "denied_at": true}

// execJSONMode is set by runExec when --json was given. A package var rather
// than a threaded parameter because the report sites sit several layers down the
// exec path and every one of them must agree.
var execJSONMode bool

// stripExecJSON removes byn's own --json flag before the child's argv, using the
// same boundary rule as the other exec flags: everything at or after `--` (or a
// bare alias name) belongs to the child and is never scanned.
func stripExecJSON(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	found := false
	boundary := false
	for _, a := range args {
		if boundary {
			out = append(out, a)
			continue
		}
		if a == "--" || !strings.HasPrefix(a, "-") {
			boundary = true
			out = append(out, a)
			continue
		}
		if a == "--json" {
			found = true
			continue
		}
		out = append(out, a)
	}
	return out, found
}

// execApprovalJSON writes one object describing a paused command to stdout.
//
// Falls back to the error's own text for any field the daemon did not supply,
// so an older daemon still produces valid JSON rather than nothing.
func execApprovalJSON(w *os.File, callErr error, exitCode int) {
	execErrorJSON(w, string(ipc.CodeApprovalPending), callErr, exitCode)
}

// execWallJSON reports a command that was refused outright.
//
// A refusal used to leave --json consumers with "exit 3 and empty stdout",
// which tells a program nothing — and this is the case where it most needs the
// facts, because the next step (stop, or ask again with --force-ask) depends on
// why and when it was refused.
func execWallJSON(w *os.File, callErr error, exitCode int) {
	execErrorJSON(w, "denied", callErr, exitCode)
}

func execErrorJSON(w *os.File, status string, callErr error, exitCode int) {
	obj := map[string]any{
		"status": status,
		"exit":   exitCode,
	}
	var em *ipc.ErrResponse
	if errors.As(callErr, &em) {
		obj["message"] = em.Message
		if em.Recover != "" {
			obj["recover"] = em.Recover
		}
		for k, v := range em.Details {
			// Timestamps travel as numbers, not strings. The details map is
			// string-keyed on the wire, and emitting it verbatim gave the same
			// field two types depending on which command produced it — a
			// consumer comparing denied_at to a clock would break on one of
			// them.
			if numericDetailKeys[k] {
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					obj[k] = n
					continue
				}
			}
			obj[k] = v
		}
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(w, string(b))
}

// stripExecDryRun removes byn's own --dry-run flag, with the same boundary rule
// as the other exec flags.
func stripExecDryRun(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	found := false
	boundary := false
	for _, a := range args {
		if boundary {
			out = append(out, a)
			continue
		}
		if a == "--" || !strings.HasPrefix(a, "-") {
			boundary = true
			out = append(out, a)
			continue
		}
		if a == "--dry-run" {
			found = true
			continue
		}
		out = append(out, a)
	}
	return out, found
}

// runExecDryRun answers whether a command would run, and whether the variables
// it needs have values — without running it.
//
// The failure it removes is discovering three minutes into a pipeline that one
// step is not pinned, or that a service will start without a credential it
// needs. Both are knowable up front. Exit 0 means it would run cleanly; 75 means
// it would pause for a decision; 1 means it would run but a required variable
// has no value.
func runExecDryRun(bynPath string, argv []string, alias string, jsonOut bool) int {
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	var resp ipc.ExecPreflightResp
	if cerr := newClient(dir, "").Call(ipc.OpExecPreflight,
		ipc.ExecPreflightReq{Path: bynPath, Argv: argv, Alias: alias}, &resp); cerr != nil {
		return handleCallError(cerr)
	}

	if jsonOut {
		b, merr := json.Marshal(resp)
		if merr != nil {
			return exitErr
		}
		_, _ = fmt.Fprintln(os.Stdout, string(b))
	} else {
		printDryRun(resp)
	}
	// The exit code must mean what the real gate means, or a caller branching on
	// it is misled in the one direction that matters. A refusal is exit 3 there,
	// not 75: a wall is not a pause, and 75 invites a retry that cannot succeed.
	switch {
	case resp.Reason == "denied":
		return exitDaemonErr
	case !resp.Pinned && !resp.Approved:
		return exitApprovalPending
	case len(resp.MissingEnv) > 0:
		return exitErr // it would run, but short of what it declares
	default:
		return exitOK
	}
}

// printDryRun renders the answer for a person, saying what to do about it.
func printDryRun(r ipc.ExecPreflightResp) {
	switch {
	case r.Pinned:
		fmt.Fprintf(os.Stderr, "%s pinned by %s\n", cyan("would run:"), cyan(r.MatchedAction))
	case r.Approved:
		fmt.Fprintf(os.Stderr, "%s not pinned, but already approved\n", cyan("would run:"))
	case r.Reason == "denied":
		msg := "was refused"
		if r.DeniedAt > 0 {
			msg += " at " + time.Unix(r.DeniedAt, 0).Format(time.RFC3339)
		}
		if r.DeniedReason != "" {
			msg += ": " + r.DeniedReason
		}
		fmt.Fprintf(os.Stderr, "%s %s\n", boldRed("would NOT run:"), msg)
		fmt.Fprintf(os.Stderr, "      %s\n", dim("ask again with: byn exec --force-ask"))
	case r.Reason == "no_actions":
		fmt.Fprintf(os.Stderr, "%s %s pins no actions, so every command needs a decision\n",
			boldYellow("would pause:"), r.Byn)
	case r.Reason == "no_match":
		fmt.Fprintf(os.Stderr, "%s not pinned in %s\n", boldYellow("would pause:"), r.Byn)
		for _, a := range r.Actions {
			fmt.Fprintf(os.Stderr, "      pinned: %s\n", dim(a))
		}
	default:
		fmt.Fprintf(os.Stderr, "%s %s (%s)\n", boldYellow("would pause:"), r.Byn, r.Reason)
	}
	if len(r.MissingEnv) > 0 {
		fmt.Fprintf(os.Stderr, "%s %s\n", boldYellow("no value for:"), strings.Join(r.MissingEnv, ", "))
		fmt.Fprintf(os.Stderr, "      set one with: %s\n",
			cyan("echo -n VALUE | byn put "+r.MissingEnv[0]))
	}
	if len(r.OptionalMissing) > 0 {
		// Information, not a problem: the .byn says the program runs without
		// these. Reported anyway, because a name marked optional by mistake is
		// invisible otherwise.
		fmt.Fprintf(os.Stderr, "%s %s\n", dim("absent, marked optional:"), dim(strings.Join(r.OptionalMissing, ", ")))
	}
	if len(r.UnattendedEnv) > 0 {
		fmt.Fprintf(os.Stderr, "%s %s\n", boldYellow("unattended value:"), strings.Join(r.UnattendedEnv, ", "))
		fmt.Fprintf(os.Stderr, "      %s\n",
			dim("stored with no password behind the call — check it is the value you meant"))
	}
}

// stripExecForceAsk removes byn's own --force-ask flag, with the same boundary
// rule as the other exec flags.
//
// It raises a fresh decision for a command that was already refused. Without it
// a refusal is a wall — deliberately, since the alternative is re-asking someone
// who just said no. The case it exists for is the human who denied by mistake.
func stripExecForceAsk(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	found := false
	boundary := false
	for _, a := range args {
		if boundary {
			out = append(out, a)
			continue
		}
		if a == "--" || !strings.HasPrefix(a, "-") {
			boundary = true
			out = append(out, a)
			continue
		}
		if a == "--force-ask" {
			found = true
			continue
		}
		out = append(out, a)
	}
	return out, found
}

// stripExecReason removes byn's own --reason flag and returns its value.
//
// It exists because of what an approval card looked like without it: "runs make
// dev", and nothing else. The owner could see what was asked and not why, so
// answering meant going and asking the agent — which is the interruption the
// queue was built to remove. byn cannot know the purpose of a command; the
// caller can, so the caller says it.
//
// --why is the same flag under the name the request was made in; both are
// accepted so neither reads as the wrong one at a glance.
//
// Same boundary rule as the other exec flags: everything after the first
// non-flag argument belongs to the child, so a child of byn can have a --reason
// of its own without byn stealing it.
func stripExecReason(args []string) ([]string, string) {
	out := make([]string, 0, len(args))
	reason := ""
	boundary := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if boundary {
			out = append(out, a)
			continue
		}
		if a == "--" || !strings.HasPrefix(a, "-") {
			boundary = true
			out = append(out, a)
			continue
		}
		if v, ok := strings.CutPrefix(a, "--reason="); ok {
			reason = v
			continue
		}
		if v, ok := strings.CutPrefix(a, "--why="); ok {
			reason = v
			continue
		}
		if (a == "--reason" || a == "--why") && i+1 < len(args) {
			reason = args[i+1]
			i++
			continue
		}
		out = append(out, a)
	}
	return out, reason
}

// stripExecAskOnce removes byn's own --once / --ask-once from an exec argv and
// reports whether it was there.
//
// It asks for a single-use grant: approving it authorizes exactly one run
// rather than leaving the command runnable for the rest of the window. An agent
// running a one-off script is the only party that knows, at the moment of
// asking, that once is enough — the approver reading a list later does not, and
// was left choosing between a wide grant and remembering to revoke.
//
// Two spellings for the same reason --reason and --why both exist: --once is
// what people write, --ask-once is what it means. The second is worth having
// because `byn approve --once` is a different act by a different party, and a
// reader who meets --once on exec first should be able to find the distinction.
//
// Same boundary rule as the other exec flags: everything after the first
// non-flag argument belongs to the child, so `byn exec -- prog --once` passes
// --once to prog rather than byn taking it.
func stripExecAskOnce(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	askOnce := false
	boundary := false
	for _, a := range args {
		if boundary {
			out = append(out, a)
			continue
		}
		if a == "--" || !strings.HasPrefix(a, "-") {
			boundary = true
			out = append(out, a)
			continue
		}
		if a == "--once" || a == "--ask-once" {
			askOnce = true
			continue
		}
		out = append(out, a)
	}
	return out, askOnce
}
