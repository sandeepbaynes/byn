package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// runRequest implements the ASKER's side of an approval: watching one's own
// request for an outcome, and withdrawing it.
//
// A separate verb from `byn approve` on purpose. Approving is what an owner
// does to somebody else's request; watching and cancelling are what the asker
// does to its own, and the two are different authorities held by different
// parties. Folding them into one command would put "answer this" and "I no
// longer need this" one flag apart.
func runRequest(args []string, scope cliScope) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: byn request watch|cancel <ticket>")
		return exitErr
	}
	switch args[0] {
	case "watch":
		return runRequestWatch(args[1:], scope)
	case "cancel":
		return runRequestCancel(args[1:], scope)
	case "help", "--help", "-h":
		fmt.Fprintln(os.Stderr, requestHelp)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "byn request: unknown subcommand %q\n", args[0])
		return exitErr
	}
}

// runRequestWatch blocks until the request is answered, then prints the outcome.
//
// JSON by default, because the caller is a program. This is the one command in
// byn whose audience is never a person: a human watching their own approval
// would simply look at the terminal they are approving in.
func runRequestWatch(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("request watch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	timeout := fs.Int("timeout", 0, "seconds to wait before giving up (default 30m, max 6h)")
	human := fs.Bool("human", false, "prose instead of JSON")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	ticket := ticketArg(fs.Args())
	if ticket == "" {
		fmt.Fprintln(os.Stderr, "Usage: byn request watch <ticket>   (or pass it on stdin)")
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	// Always send an explicit window, and hold the connection longer than it.
	//
	// A watch is one IPC round-trip that lasts as long as the wait, and the
	// client caps a round-trip at 60 seconds. So the first real watch died at
	// exactly 60s with "i/o timeout" while the decision it wanted was recorded
	// correctly in the queue — the answer arrived and there was nobody left on
	// the line. The integration test missed it because the decision came back in
	// under a second and never approached the cap.
	seconds := *timeout
	if seconds <= 0 {
		seconds = defaultWatchSeconds
	}
	c := newClient(dir, scope.Vault)
	c.Timeout = watchClientTimeout(seconds)
	var resp ipc.ApprovalWatchResp
	if cerr := c.Call(ipc.OpApprovalWatch,
		ipc.ApprovalWatchReq{Ticket: ticket, TimeoutSeconds: seconds}, &resp); cerr != nil {
		return handleCallError(cerr)
	}
	if !*human {
		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		return watchExitCode(resp)
	}
	renderWatchOutcome(resp)
	return watchExitCode(resp)
}

// watchExitCode maps an outcome to an exit status a script can branch on
// without parsing anything.
//
// Distinct codes for distinct outcomes: a shell that treats "denied" and "still
// waiting" the same will retry a refusal forever, which is the loop the whole
// approval queue exists to prevent.
func watchExitCode(r ipc.ApprovalWatchResp) int {
	switch {
	case r.TimedOut:
		return exitApprovalPending
	case r.Status == "approved" || r.Status == "used":
		return exitOK
	default: // denied, expired, cancelled, revoked
		return exitDaemonErr
	}
}

func renderWatchOutcome(r ipc.ApprovalWatchResp) {
	switch {
	case r.TimedOut:
		fmt.Fprintf(os.Stderr, "%s %s\n", boldYellow("Still waiting:"), dim("nobody has answered "+r.ApprovalID+" yet"))
		return
	case r.Status == "approved":
		verb := roleGood("approved")
		if r.Once {
			verb += dim(" (single use)")
		}
		fmt.Fprintf(os.Stderr, "%s  %s\n", verb, dim(r.ApprovalID))
	case r.Status == "cancelled":
		fmt.Fprintf(os.Stderr, "%s  %s\n", roleNote("withdrawn"), dim(r.ApprovalID))
	default:
		fmt.Fprintf(os.Stderr, "%s  %s\n", roleBad(r.Status), dim(r.ApprovalID))
	}
	// The decider's words, when they said any. This is the only place they reach
	// the asker, and for a refusal they are the difference between fixing the
	// request and re-asking the same thing.
	if r.Reason != "" {
		fmt.Fprint(os.Stderr, fieldRow("why", r.Reason))
	}
	if r.DecidedVia != "" {
		fmt.Fprint(os.Stderr, fieldRow("via", r.DecidedVia))
	}
}

// runRequestCancel withdraws a request the asker no longer needs.
func runRequestCancel(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("request cancel", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	ticket := ticketArg(fs.Args())
	if ticket == "" {
		fmt.Fprintln(os.Stderr, "Usage: byn request cancel <ticket>   (or pass it on stdin)")
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	var resp ipc.ApprovalCancelResp
	if cerr := newClient(dir, scope.Vault).Call(ipc.OpApprovalCancel,
		ipc.ApprovalCancelReq{Ticket: ticket}, &resp); cerr != nil {
		return handleCallError(cerr)
	}
	if *jsonOut {
		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		return exitOK
	}
	// A cancel that raced a decision reports the decision. Saying "withdrawn"
	// when the owner had already answered would tell the asker its question is
	// gone while a live grant sits in the queue.
	if resp.Status == "cancelled" {
		fmt.Fprintf(os.Stderr, "%s  %s\n", roleNote("withdrawn"), dim(resp.ApprovalID))
	} else {
		fmt.Fprintf(os.Stderr, "%s %s\n", boldYellow("Already "+resp.Status+":"),
			dim(resp.ApprovalID+" was answered before the cancel arrived"))
	}
	return exitOK
}

// ticketArg takes the ticket from argv, or from stdin when it is piped.
//
// Piping matters: a ticket is a capability, and an argument is visible in `ps`
// to every process on the machine for as long as the command runs. byn refuses
// secrets on the command line elsewhere for exactly this reason, and a watch
// ticket is no different in kind — anyone who reads one can answer for the agent
// that owns it or withdraw its request.
func ticketArg(rest []string) string {
	if len(rest) > 0 && rest[0] != "-" {
		return rest[0]
	}
	if stdinIsTTY() {
		return ""
	}
	line, err := readFirstLineStdin()
	if err != nil {
		return ""
	}
	return string(line)
}

// requestHelp is the asker's half of the approval system, written for the
// program that will read it rather than for a person browsing.
const requestHelp = `byn request — the asker's side of an approval

Usage:
  byn request watch  <ticket> [--timeout SECONDS] [--human]
  byn request cancel <ticket> [--json]

A watch ticket is handed to you ONCE, in the "watch_ticket" field of the
approval_pending response that raised the request. Keep it: there is no way to
ask for it again, and no command returns one for an existing request. That is
deliberate — a way to re-request a ticket would be a way for anything else on
the machine to request yours, and then answer for you or withdraw your request.

A retry that re-attaches to a request already waiting does not get a ticket
either. Only the caller that actually raised the question holds one.

  watch    Block until the request is answered, then print the outcome as JSON:
           {"approval_id","status","reason","decided_via","once","granted_until"}
           status is approved | denied | expired | cancelled | revoked, or
           pending with "timed_out":true when you stopped waiting first.
           The decider's reason reaches you here and nowhere else.

           Exit: 0 approved · 3 denied/expired/cancelled · 4 still pending.
           Branch on the code; a script that treats "denied" and "not yet" alike
           will retry a refusal for ever.

  cancel   Withdraw a request you no longer need, so nobody spends attention
           answering it. Cancelling is not denying: it leaves no mark on the
           owner's answer history and counts toward no cooldown.

Pass the ticket on stdin instead of argv when you can — an argument is visible
in "ps" to every process on the machine while the command runs.`

// defaultWatchSeconds mirrors the daemon's default wait. The CLI sends it
// explicitly rather than sending zero and letting the daemon choose, so the two
// sides cannot disagree about how long the wait is — which is the disagreement
// that broke the first live watch.
const defaultWatchSeconds = 30 * 60

// maxWatchSeconds mirrors the daemon's ceiling. Asking for longer is not an
// error; the daemon clamps, and the client simply must not hang up first.
const maxWatchSeconds = 6 * 60 * 60

// watchClientTimeout is how long the CLI holds the connection open for a watch
// of the given length.
//
// Strictly longer than the wait itself, always. The server returns a "still
// pending, you stopped waiting" answer at the end of its window, and that answer
// is useful — it tells an agent the request is alive and unanswered. If the
// client hangs up first, that answer is replaced by a transport error, which
// says nothing about the approval and looks like byn is broken.
func watchClientTimeout(watchSeconds int) time.Duration {
	if watchSeconds > maxWatchSeconds {
		watchSeconds = maxWatchSeconds // the daemon clamps here too
	}
	return time.Duration(watchSeconds)*time.Second + watchTimeoutSlack
}

// watchTimeoutSlack covers the round-trip either side of the wait itself.
const watchTimeoutSlack = 30 * time.Second
