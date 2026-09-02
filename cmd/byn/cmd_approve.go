package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
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
	revoke := fs.Bool("revoke", false, "take back a grant already given (no password — it only removes capability)")
	reason := fs.String("reason", "", "why, in your own words — shown to whoever asked (most useful with --deny)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	all := fs.Bool("all", false, "answer every pending request")
	history := fs.Bool("history", false, "show decided and expired requests too, not just what is waiting")
	once := fs.Bool("once", false,
		"single-use: the grant is spent the first time byn authorizes a run with it")
	anyone := fs.Bool("anyone", false,
		"let anything in that project use the approved command, not only whoever asked")
	grantFor := fs.Duration("for", 0, "how long an approved command runs free (default 6h, max 24h)")
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
		return listApprovals(c, *jsonOut, *history)
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
	if !*deny && !*revoke {
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
			ID: id, Approve: !*deny && !*revoke, Revoke: *revoke,
			Via: "terminal", Reason: *reason, Password: password,
			GrantForSeconds: int(*grantFor / time.Second),
			Anyone:          *anyone,
			Once:            *once,
		}, &resp)
		if cerr != nil {
			rc = handleCallError(cerr)
			continue
		}
		verb := cyan("approved")
		if resp.Entry.Status != "approved" {
			verb = yellow(resp.Entry.Status)
		}
		if *revoke {
			verb = yellow("revoked")
		}
		fmt.Fprintf(os.Stderr, "%s  %s  %s\n", verb, cyan(resp.Entry.ID), resp.Entry.Subject)
		// What the grant now IS, said once at the moment of granting it: how
		// long it lasts, and whether whoever asked is still there to use it.
		if resp.Entry.Status == "approved" && resp.Entry.GrantedUntil > 0 {
			left := time.Until(time.Unix(resp.Entry.GrantedUntil, 0)).Truncate(time.Minute)
			who := "for whoever asked"
			if resp.Entry.Anyone {
				who = "for anything in that project"
			}
			if resp.Entry.Once {
				fmt.Fprintf(os.Stderr, "          %s\n",
					dim(fmt.Sprintf("single use, %s — spent on the first run, or in %s if never used", who, left)))
			} else {
				fmt.Fprintf(os.Stderr, "          %s\n",
					dim(fmt.Sprintf("runs free for %s, %s — pin it in [exec] actions to make it permanent",
						left, who)))
			}
		}
		if resp.Entry.Late {
			fmt.Fprintf(os.Stderr, "          %s\n",
				yellow("late: whoever asked had stopped waiting — they must run it again"))
		}
	}
	return rc
}

// listApprovals shows what is waiting, or — with history — what was decided too.
//
// The default stays pending-only because that is the list a person acts on. But
// once answered, a request simply vanished, and the caller that raised it had no
// way to find out what happened short of running the command again to see. That
// is the wrong way to learn you were refused.
func listApprovals(c *ipc.Client, jsonOut, history bool) int {
	status := "pending"
	if history {
		status = "" // everything the queue still holds
	}
	var resp ipc.ApprovalListResp
	if cerr := c.Call(ipc.OpApprovalList,
		ipc.ApprovalListReq{Status: status}, &resp); cerr != nil {
		return handleCallError(cerr)
	}
	if jsonOut {
		out, merr := json.MarshalIndent(resp.Entries, "", "  ")
		if merr != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), merr)
			return exitErr
		}
		_, _ = fmt.Fprintln(os.Stdout, string(out))
		return exitOK
	}
	if len(resp.Entries) == 0 {
		if history {
			fmt.Fprintln(os.Stderr, dim("No requests on file."))
		} else {
			fmt.Fprintln(os.Stderr, dim("Nothing waiting.")+dim("  (byn approve --history for decided ones)"))
		}
		return exitOK
	}
	// Two shapes for two jobs. A handful of pending requests are records you
	// READ — the reason and the asker are the decision. Dozens of decided ones
	// are rows you SCAN, and the same layout does not serve both.
	now := time.Now()
	if history {
		renderHistoryTable(os.Stdout, resp.Entries, now, termWidthStdout())
		fmt.Fprintf(os.Stderr, "\n%s\n", dim("Columns are truncated to your terminal; byn approve --history --json has every field in full."))
		return exitOK
	}
	for _, e := range resp.Entries {
		renderPendingEntry(os.Stdout, e, now)
	}
	if !history {
		// Named whenever there is something to see, not only when the queue is
		// empty. A request that expires leaves nothing on screen, so an owner
		// who never learns this flag exists is left with "the agent said it
		// asked for something" and no way to find out what.
		if n := decidedCount(c); n > 0 {
			fmt.Fprintf(os.Stderr, "\n%s\n",
				dim(fmt.Sprintf("%d decided or expired request(s) — byn approve --history to see what was asked, and why", n)))
		}
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", dim("Approving authorizes; it runs nothing and edits no file. Whoever asked runs it again."))
	// Said once for the list, not once per card. It used to be printed under
	// every entry — the same 100-character sentence repeated down the screen,
	// which is most of what made the list feel scattered. It is still worth
	// saying: both kinds were read as "byn will now do this", and one as a
	// proposed edit to the .byn. Neither is true.
	for _, note := range kindNotes(resp.Entries) {
		fmt.Fprintf(os.Stderr, "%s\n", dim("  "+note))
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Grant:"), cyan("byn approve <id>"))
	fmt.Fprintf(os.Stderr, "%s %s\n", dim("       "),
		dim("add --for 30m to shorten the window a command runs free (default 6h)"))
	fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Refuse:"), cyan("byn approve --deny <id>"))
	// Named next to refuse because they are easily confused, and the confusion
	// is expensive: --deny on something already approved does NOT take the
	// grant back, and an owner who assumed it did would be wrong about what is
	// still runnable.
	fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Revoke:"), cyan("byn approve --revoke <id>")+
		dim("   take back a grant already given"))
	// A refusal stops the asker until someone changes something, so the single
	// most useful thing to hand back is why.
	fmt.Fprintf(os.Stderr, "%s %s\n", dim("       "), dim("add --reason \"wrong target\" — the asker is told, and it is in the audit log"))
	return exitOK
}

// kindNotes returns the per-kind explanations relevant to THIS list, each at
// most once, in a stable order. A list of one kind gets one line; a list of
// both gets two; an empty list gets none.
func kindNotes(entries []ipc.ApprovalEntry) []string {
	var out []string
	for _, kind := range []string{"action_unpinned", "trust_widening"} {
		for _, e := range entries {
			if e.Kind == kind {
				if note := whatApprovingDoes(kind); note != "" {
					out = append(out, note)
				}
				break
			}
		}
	}
	return out
}

// whatApprovingDoes says, per kind, what a yes actually does.
//
// Both kinds were being read as "byn will now do this thing", and one of them
// was being read as a proposed edit to the .byn file. Neither is true: nothing
// is run and nothing is written to the project. Saying so on the card is
// cheaper than the conversation that follows when it is left implicit.
func whatApprovingDoes(kind string) string {
	switch kind {
	case "action_unpinned":
		return "approving lets this command run when it is next attempted — it does not run now, " +
			"and the .byn is not changed"
	case "trust_widening":
		return "approving grants the .byn what it already asks for — it does not edit the file, " +
			"and nothing runs until it is attempted again"
	default:
		return ""
	}
}

// oneLine renders a summary line for a list: newlines collapsed, length capped.
//
// The text itself is never rewritten in the record — it is what the request
// fingerprint is computed from, so changing it would invalidate pending
// requests and existing grants. This is presentation only.
func oneLine(s string, limit int) string {
	s = strings.Join(strings.Fields(s), " ")
	return ellipsize(s, limit)
}

// decidedCount counts requests that are no longer pending, so the pending list
// can say how much history is behind it. Best-effort: a count byn cannot get is
// simply not mentioned.
func decidedCount(c *ipc.Client) int {
	var all ipc.ApprovalListResp
	if err := c.Call(ipc.OpApprovalList, ipc.ApprovalListReq{}, &all); err != nil {
		return 0
	}
	n := 0
	for _, e := range all.Entries {
		if e.Status != "pending" {
			n++
		}
	}
	return n
}
