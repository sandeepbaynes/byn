package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// byn runs — what past executions were given.
//
// The record answers a question that only gets asked afterwards: which values
// did that process hold, run by what, from where, and when. Listing is
// metadata, and byn already lists variable names without a credential, so it
// asks for none.
//
// --reveal is a different act. It hands over the values themselves, so it is
// gated exactly as reading a secret is, and it says so before it does it: an
// audit that quietly prints secrets is a way to read secrets.
func runRuns(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("runs", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "output as JSON")
	limit := fs.Int("n", 20, "how many runs to show")
	reveal := fs.Bool("reveal", false, "show the VALUES the run received (needs the master password)")
	pwStdin := fs.Bool("password-stdin", false, "read the authorizing password from stdin")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}

	var id int64
	diff := false
	rest := fs.Args()
	if len(rest) > 0 && (rest[0] == "show" || rest[0] == "diff") {
		// `byn runs diff <id>` is the safe answer to the audit question: what
		// became of each value, with none of them printed. Named for what it
		// does — the digests recorded for the run against the vault now — and
		// deliberately not "verify", which in this CLI already means the
		// cryptographic check that `byn audit verify` performs.
		diff = rest[0] == "diff"
		rest = rest[1:]
	}
	if len(rest) > 0 {
		n, perr := strconv.ParseInt(rest[0], 10, 64)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "%s not a run id: %q\n", boldRed("Error:"), rest[0])
			return exitErr
		}
		id = n
	}
	if *reveal && id == 0 {
		fmt.Fprintf(os.Stderr, "%s --reveal needs one run: byn runs show <id> --reveal\n", boldRed("Error:"))
		return exitErr
	}
	if diff && id == 0 {
		fmt.Fprintf(os.Stderr, "%s diff needs one run: byn runs diff <id>\n", boldRed("Error:"))
		return exitErr
	}

	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}

	if *reveal && !*jsonOut {
		// Said before it happens, not after. Whoever runs this should know they
		// are about to put secrets on a terminal — and if they are running it
		// on someone's behalf, that they are about to show them to that person.
		fmt.Fprintf(os.Stderr, "%s this prints the SECRET VALUES run %d received.\n",
			boldYellow("Warning:"), id)
		fmt.Fprintf(os.Stderr, "         %s\n",
			dim("they will appear on this terminal and in anything capturing it"))
		// Offered here because this is where the mistake happens. Someone
		// asking "was this rotated?" reached for the only command that answers
		// it, and it prints every secret the run held — once, into a chat
		// window. The question has its own command; say so at the moment the
		// wrong one is being run.
		fmt.Fprintf(os.Stderr, "         %s\n",
			dim(fmt.Sprintf("only need to know what changed? byn runs diff %d — no values, no password", id)))
	}

	req := ipc.RunListReq{Scope: scope.ToIPC(), Limit: *limit, ID: id, Reveal: *reveal, Diff: diff}
	var resp ipc.RunListResp
	rc := mutateWithAuthRetry(*pwStdin, *jsonOut, false, nil, func(pw []byte) error {
		req.Password = pw
		return newClient(dir, scope.Vault).Call(ipc.OpRunList, req, &resp)
	})
	if rc != exitOK {
		return rc
	}

	if *jsonOut {
		out, merr := json.MarshalIndent(resp.Entries, "", "  ")
		if merr != nil {
			return exitErr
		}
		fmt.Println(string(out))
		return exitOK
	}
	if len(resp.Entries) == 0 {
		fmt.Fprintln(os.Stderr, dim("no runs recorded"))
		return exitOK
	}
	for _, e := range resp.Entries {
		printRun(e, id != 0)
	}
	if diff {
		fmt.Fprintf(os.Stderr, "\n%s\n",
			dim("no values were read. byn runs show <id> --reveal shows them, and asks for the password."))
	}
	return exitOK
}

// printRun renders one run for a person.
func printRun(e ipc.RunEntry, detailed bool) {
	when := time.Unix(e.At, 0).Format(time.RFC3339)
	who := e.CallerComm
	if who == "" {
		who = "?"
	}
	if e.CallerAgent > 0 {
		// The same rendering an approval card uses. Two spellings of one
		// identity read as two facts, and someone comparing a card against a
		// run record should not have to work out that they match.
		if e.CallerAgentComm != "" {
			who = fmt.Sprintf("%s (pid %d)", e.CallerAgentComm, e.CallerAgent)
		} else {
			who += fmt.Sprintf(" (agent %d)", e.CallerAgent)
		}
	}
	cmd := e.Command
	if !detailed {
		// One line per run in the list. A `node -e '<300 characters>'` turned a
		// single entry into five lines and pushed the rest off the screen; the
		// whole command is still in `runs show` and in --json.
		cmd = ellipsize(cmd, 80)
	}
	fmt.Printf("%s %s  %s\n", cyan(fmt.Sprintf("#%d", e.ID)), when, cmd)
	fmt.Printf("     %s\n", dim(fmt.Sprintf("%s · %s · %d value(s)", who, e.Byn, e.VarCount)))
	if !detailed {
		return
	}
	if len(e.Names) > 0 && e.Values == nil && len(e.Status) == 0 {
		fmt.Printf("     %s %s\n", dim("received:"), dim(strings.Join(markUnattended(e), ", ")))
	}
	for _, n := range e.Names {
		if v, ok := e.Values[n]; ok {
			fmt.Printf("     %s=%s\n", n, v)
		}
	}
	printStatus(e)
}

// markUnattended annotates the names a run received, flagging the ones byn took
// in with no credential behind them.
//
// A value the owner provisioned and one an agent invented shape a program
// identically, and the run record is where someone goes to tell them apart
// afterwards — the launch warning has long since scrolled away.
func markUnattended(e ipc.RunEntry) []string {
	if len(e.Unattended) == 0 {
		return e.Names
	}
	flagged := make(map[string]struct{}, len(e.Unattended))
	for _, n := range e.Unattended {
		flagged[n] = struct{}{}
	}
	out := make([]string, 0, len(e.Names))
	for _, n := range e.Names {
		if _, ok := flagged[n]; ok {
			n += " (unattended)"
		}
		out = append(out, n)
	}
	return out
}

// ellipsize shortens a line to fit, marking that it was cut.
func ellipsize(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "\u2026"
}

// printStatus says what became of the values a run used.
//
// Each wording is a different claim and they are not interchangeable:
// "changed since" means the entry is still there and holds a different blob;
// "deleted since" means the entry the run used is gone — including a name
// deleted and re-created, which is a new entry, not a new version of the old
// one; "could not be read" means byn failed, which is a statement about byn and
// not about the value's history.
func printStatus(e ipc.RunEntry) {
	if len(e.Status) == 0 {
		return
	}
	groups := map[string][]string{}
	for name, st := range e.Status {
		groups[st] = append(groups[st], name)
	}
	for _, g := range []struct {
		status, label, note string
	}{
		{"changed", "changed since:",
			"byn keeps no copy of a replaced value, so these cannot be shown"},
		{"deleted", "deleted since:",
			"the entry this run used is gone — a name re-created since is a new entry, not this one"},
		{"unreadable", "could not be read:",
			"byn could not open these; that is about byn, not evidence the value changed"},
	} {
		names := groups[g.status]
		if len(names) == 0 {
			continue
		}
		sort.Strings(names)
		fmt.Printf("     %s %s\n", yellow(g.label), strings.Join(names, ", "))
		fmt.Printf("     %s\n", dim(g.note))
	}
	if unchanged := groups["unchanged"]; len(unchanged) > 0 {
		sort.Strings(unchanged)
		fmt.Printf("     %s %s\n", dim("unchanged:"), dim(strings.Join(unchanged, ", ")))
	}
}
