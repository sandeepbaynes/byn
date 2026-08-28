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
	reason := fs.String("reason", "", "why, in your own words — shown to whoever asked (most useful with --deny)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	all := fs.Bool("all", false, "answer every pending request")
	history := fs.Bool("history", false, "show decided and expired requests too, not just what is waiting")
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
			ID: id, Approve: !*deny, Via: "terminal", Reason: *reason, Password: password,
			GrantForSeconds: int(*grantFor / time.Second),
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
		// What the grant now IS, said once at the moment of granting it: how
		// long it lasts, and whether whoever asked is still there to use it.
		if resp.Entry.Status == "approved" && resp.Entry.GrantedUntil > 0 {
			left := time.Until(time.Unix(resp.Entry.GrantedUntil, 0)).Truncate(time.Minute)
			fmt.Fprintf(os.Stderr, "          %s\n",
				dim(fmt.Sprintf("runs free for %s — pin it in [exec] actions to make it permanent", left)))
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
	for _, e := range resp.Entries {
		marker := " "
		if e.HighRisk {
			marker = boldYellow("!")
		}
		_, _ = fmt.Fprintf(os.Stdout, "%s %s  %s\n", marker, cyan(e.ID), e.Subject)
		for _, line := range e.Summary {
			_, _ = fmt.Fprintf(os.Stdout, "      %s\n", line)
		}
		// What approving would DO. "runs make dev" reads like a button that
		// runs make dev, and the first question anyone asked of these cards was
		// whether approving executed something. It does not: it authorizes, and
		// whoever asked has to come back and run it themselves.
		if what := whatApprovingDoes(e.Kind); what != "" {
			_, _ = fmt.Fprintf(os.Stdout, "      %s\n", dim(what))
		}
		// Why, in the asker's words — labelled as the claim it is. byn cannot
		// check a stated purpose and does not pretend to; an unverified sentence
		// still beats a card that says nothing about what the command is for.
		if e.Reason != "" {
			_, _ = fmt.Fprintf(os.Stdout, "      %s %s\n", yellow("why:"), e.Reason)
			_, _ = fmt.Fprintf(os.Stdout, "      %s\n", dim("     (said by whoever asked — byn cannot verify it)"))
		} else if e.Status == "pending" {
			_, _ = fmt.Fprintf(os.Stdout, "      %s\n",
				dim("no reason given — an agent can pass one with byn exec --reason \"…\""))
		}
		// Who asked, from the kernel rather than from the request. This is the
		// half byn can vouch for, and it is what tells you whether your own
		// agent asked or something else in the same project did.
		if who := e.Requestor.Display; who != "" {
			line := who
			if e.Requestor.Cwd != "" {
				line += " in " + e.Requestor.Cwd
			}
			_, _ = fmt.Fprintf(os.Stdout, "      %s %s\n", cyan("who:"), line)
		}
		age := time.Since(time.Unix(e.CreatedAt, 0)).Truncate(time.Second)
		detail := fmt.Sprintf("asked %s ago", age)
		if e.Status != "pending" {
			// An answered request: what happened is the useful part, not its age.
			detail = e.Status
			if e.DecidedAt > 0 {
				detail += " " + time.Since(time.Unix(e.DecidedAt, 0)).Truncate(time.Second).String() + " ago"
			}
			if e.DecidedVia != "" {
				detail += " via " + e.DecidedVia
			}
			if e.DecidedReason != "" {
				detail += " — " + e.DecidedReason
			}
			if e.Late {
				// The grant is real; the process that wanted it is not. Worth
				// saying, because otherwise a granted-and-unused command looks
				// exactly like one that ran.
				detail += ", answered after the asker gave up"
			}
			// For a granted command, say whether it still runs free. An
			// approval that has simply timed out otherwise looks exactly like
			// one that was never there.
			if e.GrantedUntil > 0 {
				if left := time.Until(time.Unix(e.GrantedUntil, 0)).Truncate(time.Minute); left > 0 {
					detail += fmt.Sprintf(", runs free for another %s", left)
				} else {
					detail += ", grant expired"
				}
			}
			_, _ = fmt.Fprintf(os.Stdout, "      %s\n", dim(detail))
			continue
		}
		// How long is left, not just how long it has been waiting. A request
		// raised at the end of a day can expire before anyone looks at it, and
		// "asked 5h ago" does not tell you that you have an hour to answer.
		if e.ExpiresAt > 0 {
			if left := time.Until(time.Unix(e.ExpiresAt, 0)).Truncate(time.Minute); left > 0 {
				detail += fmt.Sprintf(", expires in %s", left)
			} else {
				detail += ", expired"
			}
		}
		if e.Repeats > 0 {
			detail += fmt.Sprintf(", retried %d×", e.Repeats)
		}
		// Whether anything is still listening. Two requests an hour apart look
		// identical on a list, and one of them may have a process sitting on it
		// right now while the other was abandoned before you sat down.
		if e.NeededBy > 0 {
			if left := time.Until(time.Unix(e.NeededBy, 0)).Truncate(time.Second); left > 0 {
				detail += fmt.Sprintf(", %s", boldYellow("needed within "+left.String()))
			} else {
				detail += ", " + dim("no longer waiting")
			}
		}
		// The vault, when it is not the default one: two projects on one
		// machine are told apart by it at a glance, and the JSON form has
		// carried it all along.
		if e.Vault != "" && e.Vault != "default" {
			detail += ", vault " + e.Vault
		}
		if e.HighRisk {
			detail += " — high risk"
		}
		_, _ = fmt.Fprintf(os.Stdout, "      %s\n", dim(detail))
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", dim("Approving authorizes; it runs nothing and edits no file. Whoever asked runs it again."))
	fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Grant:"), cyan("byn approve <id>"))
	fmt.Fprintf(os.Stderr, "%s %s\n", dim("       "),
		dim("add --for 30m to shorten the window a command runs free (default 6h)"))
	fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Refuse:"), cyan("byn approve --deny <id>"))
	// A refusal stops the asker until someone changes something, so the single
	// most useful thing to hand back is why.
	fmt.Fprintf(os.Stderr, "%s %s\n", dim("       "), dim("add --reason \"wrong target\" — the asker is told, and it is in the audit log"))
	return exitOK
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
