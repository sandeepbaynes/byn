package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// runApprove lists queued decisions, or answers one.
//
//	byn approve                 # what is waiting
//	byn approve <id>            # grant it (asks for the master password)
//	byn approve --deny <id>     # refuse it
//
// Approving grants authority and so requires the master password, the same
// proof of presence `byn trust` demands. Denying asks for nothing and requires
// none, which keeps refusal the cheaper action.
func runApprove(args []string, _ cliScope) int {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	deny := fs.Bool("deny", false, "refuse the request instead of granting it")
	jsonOut := fs.Bool("json", false, "output as JSON")
	all := fs.Bool("all", false, "answer every pending request")
	pwStdin := fs.Bool("password-stdin", false, "read the master password from stdin")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}

	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	c := newClient(dir, "")

	ids := fs.Args()
	if len(ids) == 0 && !*all {
		return listApprovals(c, *jsonOut)
	}

	if *all {
		var list ipc.ApprovalListResp
		if cerr := c.Call(ipc.OpApprovalList,
			ipc.ApprovalListReq{Status: "pending"}, &list); cerr != nil {
			return handleCallError(cerr)
		}
		if len(list.Entries) == 0 {
			fmt.Fprintln(os.Stderr, dim("Nothing waiting."))
			return exitOK
		}
		for _, e := range list.Entries {
			ids = append(ids, e.ID)
		}
	}

	// One password covers the whole batch: asking per request would make
	// answering a backlog its own chore, and a chore is what turns review into
	// reflex.
	var password []byte
	var wipe func()
	if !*deny {
		password, wipe, err = authorizingPasswordWithLeadIn(*pwStdin,
			yellow("Approving grants authority — the master password is proof you are here."))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
			return exitErr
		}
		defer wipe()
	}

	rc := exitOK
	for _, id := range ids {
		var resp ipc.ApprovalDecideResp
		cerr := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
			ID: id, Approve: !*deny, Via: "terminal", Password: password,
		}, &resp)
		if cerr != nil {
			rc = handleCallError(cerr)
			continue
		}
		verb := cyan("approved")
		if resp.Entry.Status != "approved" {
			verb = yellow(resp.Entry.Status)
		}
		fmt.Fprintf(os.Stderr, "%s  %s  %s\n", verb, cyan(resp.Entry.ID), resp.Entry.Subject)
	}
	return rc
}

func listApprovals(c *ipc.Client, jsonOut bool) int {
	var resp ipc.ApprovalListResp
	if cerr := c.Call(ipc.OpApprovalList,
		ipc.ApprovalListReq{Status: "pending"}, &resp); cerr != nil {
		return handleCallError(cerr)
	}
	if jsonOut {
		out, merr := json.MarshalIndent(resp.Entries, "", "  ")
		if merr != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), merr)
			return exitErr
		}
		fmt.Fprintln(os.Stdout, string(out))
		return exitOK
	}
	if len(resp.Entries) == 0 {
		fmt.Fprintln(os.Stderr, dim("Nothing waiting."))
		return exitOK
	}
	for _, e := range resp.Entries {
		marker := " "
		if e.HighRisk {
			marker = boldYellow("!")
		}
		fmt.Fprintf(os.Stdout, "%s %s  %s\n", marker, cyan(e.ID), e.Subject)
		for _, line := range e.Summary {
			fmt.Fprintf(os.Stdout, "      %s\n", line)
		}
		age := time.Since(time.Unix(e.CreatedAt, 0)).Truncate(time.Second)
		detail := fmt.Sprintf("asked %s ago", age)
		if e.Repeats > 0 {
			detail += fmt.Sprintf(", retried %d×", e.Repeats)
		}
		if e.HighRisk {
			detail += " — high risk"
		}
		fmt.Fprintf(os.Stdout, "      %s\n", dim(detail))
	}
	fmt.Fprintf(os.Stderr, "\n%s %s\n", yellow("Grant:"), cyan("byn approve <id>"))
	fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Refuse:"), cyan("byn approve --deny <id>"))
	return exitOK
}
