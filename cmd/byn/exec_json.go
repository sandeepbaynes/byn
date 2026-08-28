package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

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
	obj := map[string]any{
		"status": string(ipc.CodeApprovalPending),
		"exit":   exitCode,
	}
	var em *ipc.ErrResponse
	if errors.As(callErr, &em) {
		obj["message"] = em.Message
		if em.Recover != "" {
			obj["recover"] = em.Recover
		}
		for k, v := range em.Details {
			switch k {
			case "expires_at":
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					obj[k] = n
					continue
				}
				obj[k] = v
			default:
				obj[k] = v
			}
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
	switch {
	case !resp.Pinned:
		return exitApprovalPending // it would pause, which is what 75 means
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
