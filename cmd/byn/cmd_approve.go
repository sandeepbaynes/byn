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
//
// The password is the one for the vault each request was raised in — no other
// proves anything about it. The vault in scope (--vault, BYN_VAULT, or this
// directory's .byn) decides what is listed and what --all answers, so an owner
// can answer another vault's requests from anywhere with --vault NAME.
func runApprove(args []string, scope cliScope) int {
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
	always := fs.Bool("always", false,
		"grant normally even though the asker asked for a single use")
	anyone := fs.Bool("anyone", false,
		"let anything in that project use the approved command, not only whoever asked")
	grantFor := fs.Duration("for", 0, "how long an approved command runs free (default 6h, 1h for ad hoc; max 24h)")
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
	inVault := approveVault(scope)

	ids := fs.Args()
	if len(ids) == 0 && !*all {
		return listApprovals(c, *jsonOut, *history, inVault)
	}

	// Everything on file, so each id can be matched to the vault it was raised
	// in: that vault's password is the only one that can approve it.
	var known ipc.ApprovalListResp
	if cerr := c.Call(ipc.OpApprovalList, ipc.ApprovalListReq{}, &known); cerr != nil {
		return handleCallError(cerr)
	}
	vaultOf := make(map[string]string, len(known.Entries))
	for _, e := range known.Entries {
		vaultOf[e.ID] = entryVault(e)
	}

	if *all {
		for _, e := range known.Entries {
			if e.Status == "pending" && inApproveScope(e, inVault) {
				ids = append(ids, e.ID)
			}
		}
		if len(ids) == 0 {
			fmt.Fprintln(os.Stderr, dim("Nothing waiting"+inVaultSuffix(inVault)+"."))
			printOtherVaults(known.Entries, inVault)
			return exitOK
		}
	}

	rc := exitOK
	// Grouped by vault, in the order first named. One password per vault covers
	// its share of the batch: asking per request would make answering a backlog
	// its own chore, and a chore is what turns review into reflex.
	var vaults []string
	byVault := map[string][]string{}
	for _, id := range ids {
		v := vaultOf[id] // "" for an id byn does not know; the daemon says so
		// A vault named on the command line is a statement about what is being
		// approved. An id from another vault contradicts it, and answering
		// anyway would be approving something other than what was said.
		if v != "" && scope.VaultNamed && v != inVault {
			fmt.Fprintf(os.Stderr, "%s %s is waiting in vault %s, not %s\n",
				boldRed("Error:"), id, v, inVault)
			fmt.Fprintf(os.Stderr, "%s byn approve --vault %s %s\n", yellow("Try:"), v, id)
			rc = exitErr
			continue
		}
		if _, seen := byVault[v]; !seen {
			vaults = append(vaults, v)
		}
		byVault[v] = append(byVault[v], id)
	}

	approving := !*deny && !*revoke
	if approving && *pwStdin && countNamed(vaults) > 1 {
		fmt.Fprintf(os.Stderr, "%s --password-stdin answers one vault, and these requests are in %s\n",
			boldRed("Error:"), strings.Join(namedOnly(vaults), ", "))
		fmt.Fprintf(os.Stderr, "%s byn approve --all --vault NAME --password-stdin\n", yellow("Try:"))
		return exitErr
	}

	base := ipc.ApprovalDecideReq{
		Approve: approving, Revoke: *revoke,
		Via: "terminal", Reason: *reason,
		GrantForSeconds: int(*grantFor / time.Second),
		Anyone:          *anyone,
		Once:            *once,
		Always:          *always,
	}
	for _, v := range vaults {
		var password []byte
		if approving && v != "" {
			pw, wipe, perr := authorizingPasswordWithLeadIn(*pwStdin, yellow(fmt.Sprintf(
				"Approving grants authority — the master password of vault %s is proof you are here.", v)))
			if perr != nil {
				fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), perr)
				return exitErr
			}
			password = pw
			defer wipe()
		}
		for _, id := range byVault[v] {
			req := base
			req.ID, req.Password = id, password
			if code := answerApproval(c, req, *revoke); code != exitOK {
				rc = code
			}
		}
	}
	return rc
}

// answerApproval sends one decision and reports what it now is.
func answerApproval(c *ipc.Client, req ipc.ApprovalDecideReq, revoke bool) int {
	var resp ipc.ApprovalDecideResp
	if cerr := c.Call(ipc.OpApprovalDecide, req, &resp); cerr != nil {
		return handleCallError(cerr)
	}
	verb := cyan("approved")
	if resp.Entry.Status != "approved" {
		verb = yellow(resp.Entry.Status)
	}
	if revoke {
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
	return exitOK
}

// approveVault is the vault `byn approve` answers for: one named with --vault
// or BYN_VAULT, else the vault of the .byn this directory is in. "" means
// neither — no vault named and no project here — so every vault is in play.
func approveVault(scope cliScope) string {
	if scope.Vault != "" {
		return scope.Vault
	}
	if scope.SourcePath != "" {
		return "default" // a .byn that names no vault uses the default one
	}
	return ""
}

// entryVault is the vault a request was raised in. Requests from before byn
// recorded one were raised in the default vault.
func entryVault(e ipc.ApprovalEntry) string {
	if e.Vault == "" {
		return "default"
	}
	return e.Vault
}

func inApproveScope(e ipc.ApprovalEntry, inVault string) bool {
	return inVault == "" || entryVault(e) == inVault
}

func inVaultSuffix(inVault string) string {
	if inVault == "" {
		return ""
	}
	return " in vault " + inVault
}

// printOtherVaults says what is waiting outside the vault in scope. Scoping the
// list to a vault must not hide a request: one nobody can see expires unanswered
// and leaves its asker stopped for no reason anyone chose.
func printOtherVaults(entries []ipc.ApprovalEntry, inVault string) {
	if inVault == "" {
		return
	}
	counts := map[string]int{}
	var order []string
	for _, e := range entries {
		v := entryVault(e)
		if e.Status != "pending" || v == inVault {
			continue
		}
		if counts[v] == 0 {
			order = append(order, v)
		}
		counts[v]++
	}
	if len(order) == 0 {
		return
	}
	parts := make([]string, 0, len(order))
	for _, v := range order {
		parts = append(parts, fmt.Sprintf("%s (%d)", v, counts[v]))
	}
	printWrapped(os.Stderr, "Also waiting in other vaults: "+strings.Join(parts, ", ")+
		" — byn approve --vault NAME", 0)
}

func namedOnly(vaults []string) []string {
	out := make([]string, 0, len(vaults))
	for _, v := range vaults {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func countNamed(vaults []string) int { return len(namedOnly(vaults)) }

// listApprovals shows what is waiting, or — with history — what was decided too.
//
// The default stays pending-only because that is the list a person acts on. But
// once answered, a request simply vanished, and the caller that raised it had no
// way to find out what happened short of running the command again to see. That
// is the wrong way to learn you were refused.
func listApprovals(c *ipc.Client, jsonOut, history bool, inVault string) int {
	// Everything on file, filtered here: the pending requests of other vaults
	// are still worth a line, and only this side knows which vault is in scope.
	var all ipc.ApprovalListResp
	if cerr := c.Call(ipc.OpApprovalList, ipc.ApprovalListReq{}, &all); cerr != nil {
		return handleCallError(cerr)
	}
	var resp ipc.ApprovalListResp
	resp.Entries = []ipc.ApprovalEntry{}
	decided := 0
	for _, e := range all.Entries {
		if !inApproveScope(e, inVault) {
			continue
		}
		if e.Status != "pending" {
			decided++
			if !history {
				continue
			}
		}
		resp.Entries = append(resp.Entries, e)
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
			fmt.Fprintln(os.Stderr, dim("No requests on file"+inVaultSuffix(inVault)+"."))
		} else {
			fmt.Fprintln(os.Stderr, dim("Nothing waiting"+inVaultSuffix(inVault)+".")+
				dim("  (byn approve --history for decided ones)"))
		}
		printOtherVaults(all.Entries, inVault)
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
	width := termWidthStdout()
	for _, e := range resp.Entries {
		renderPendingEntry(os.Stdout, e, now, width)
	}
	if !history {
		// Named whenever there is something to see, not only when the queue is
		// empty. A request that expires leaves nothing on screen, so an owner
		// who never learns this flag exists is left with "the agent said it
		// asked for something" and no way to find out what.
		if n := decided; n > 0 {
			fmt.Fprintln(os.Stderr)
			printWrapped(os.Stderr, fmt.Sprintf(
				"%d decided or expired request(s) — byn approve --history to see what was asked, and why", n), 0)
		}
	}
	printOtherVaults(all.Entries, inVault)
	fmt.Fprintln(os.Stderr)
	printWrapped(os.Stderr, "Approving authorizes; it runs nothing and edits no file. Whoever asked runs it again.", 0)
	// Said once for the list, not once per card. It used to be printed under
	// every entry — the same 100-character sentence repeated down the screen,
	// which is most of what made the list feel scattered. It is still worth
	// saying: both kinds were read as "byn will now do this", and one as a
	// proposed edit to the .byn. Neither is true.
	for _, note := range kindNotes(resp.Entries) {
		printWrapped(os.Stderr, "  "+note, 2)
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Grant:"), cyan("byn approve <id>"))
	printWrapped(os.Stderr, "        add --for 30m to shorten the window each card says it lasts, or --once for a single run", 8)
	fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Refuse:"), cyan("byn approve --deny <id>"))
	// Named next to refuse because they are easily confused, and the confusion
	// is expensive: --deny on something already approved does NOT take the
	// grant back, and an owner who assumed it did would be wrong about what is
	// still runnable.
	fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Revoke:"), cyan("byn approve --revoke <id>")+
		dim("   take back a grant already given"))
	// A refusal stops the asker until someone changes something, so the single
	// most useful thing to hand back is why.
	printWrapped(os.Stderr, "        add --reason \"wrong target\" — the asker is told, and it is in the audit log", 8)
	return exitOK
}

// kindNotes returns the per-kind explanations relevant to THIS list, each at
// most once, in a stable order. A list of one kind gets one line; a list of
// both gets two; an empty list gets none.
func kindNotes(entries []ipc.ApprovalEntry) []string {
	var out []string
	for _, kind := range []string{"action_unpinned", "adhoc", "trust_widening"} {
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
	case "adhoc":
		return "approving lets this command run when it is next attempted, with exactly the variables " +
			"listed — it does not run now, and no .byn is written or changed"
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
