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
