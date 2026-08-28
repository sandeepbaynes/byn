package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
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
	rest := fs.Args()
	if len(rest) > 0 && rest[0] == "show" {
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
	}

	req := ipc.RunListReq{Scope: scope.ToIPC(), Limit: *limit, ID: id, Reveal: *reveal}
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
		who += fmt.Sprintf(" (agent %d)", e.CallerAgent)
	}
	fmt.Printf("%s %s  %s\n", cyan(fmt.Sprintf("#%d", e.ID)), when, e.Command)
	fmt.Printf("     %s\n", dim(fmt.Sprintf("%s · %s · %d value(s)", who, e.Byn, e.VarCount)))
	if !detailed {
		return
	}
	if len(e.Names) > 0 && e.Values == nil {
		fmt.Printf("     %s %s\n", dim("received:"), dim(strings.Join(e.Names, ", ")))
	}
	for _, n := range e.Names {
		if v, ok := e.Values[n]; ok {
			fmt.Printf("     %s=%s\n", n, v)
		}
	}
	if len(e.Superseded) > 0 {
		fmt.Printf("     %s %s\n", yellow("changed since:"), strings.Join(e.Superseded, ", "))
		fmt.Printf("     %s\n", dim("byn keeps no copy of a replaced value, so these cannot be shown"))
	}
}
