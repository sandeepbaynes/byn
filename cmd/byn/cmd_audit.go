// `byn audit` — read and verify the per-vault audit log.
//
//	byn audit tail [--lines N] [--json]
//	byn audit verify
//
// The log is metadata only (plain-text names, scope, op, outcome,
// HMAC chain entry); reading it does not require the vault to be
// unlocked. The HMAC chain is verifiable with just the seed in the
// meta table, also accessible while locked.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func runAudit(args []string, scope cliScope) int {
	if len(args) == 0 {
		printAuditUsage(os.Stderr)
		return exitErr
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "view", "log":
		return runAuditView(rest, scope)
	case "tail":
		return runAuditTail(rest, scope)
	case "verify":
		return runAuditVerify(rest, scope)
	case "reseal":
		return runAuditReseal(rest, scope)
	case "help", "--help", "-h":
		printAuditUsage(os.Stdout)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "byn audit: unknown subcommand %q\n", sub)
		printAuditUsage(os.Stderr)
		return exitErr
	}
}

// runAuditView prints a snapshot of the last N events and exits.
func runAuditView(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("audit view", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	lines := fs.Int("lines", 50, "max events to show (0 = all)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	bynF := fs.String("byn", "", "filter: events whose .byn path matches (substring)")
	callerF := fs.String("caller", "", "filter: events whose caller matches (substring)")
	scopeF := fs.String("scope", "", "filter: events in a matching project[/env] (substring)")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	var resp ipc.AuditTailResp
	if err := newClient(dir, scope.Vault).Call(ipc.OpAuditTail,
		ipc.AuditTailReq{Vault: scope.Vault, Lines: *lines, Byn: *bynF, Caller: *callerF, Scope: *scopeF}, &resp); err != nil {
		return handleCallError(err)
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(resp.Events, "", "  ")
		fmt.Println(string(out))
		return exitOK
	}
	if len(resp.Events) == 0 {
		fmt.Fprintln(os.Stderr, "(no audit events recorded yet)")
		return exitOK
	}
	for _, e := range resp.Events {
		fmt.Println(auditLine(e))
	}
	return exitOK
}

// runAuditTail mirrors bash `tail`: print the last N events and exit, or
// with -f keep streaming new events in realtime (Ctrl-C to stop). Flags
// mirror tail for familiarity: -n N, -f.
func runAuditTail(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("audit tail", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	n := fs.Int("n", 10, "number of trailing events to start with")
	linesAlias := fs.Int("lines", -1, "alias for -n")
	follow := fs.Bool("f", false, "follow: stream new events in realtime (Ctrl-C to stop)")
	jsonOut := fs.Bool("json", false, "output as JSON (NDJSON when following)")
	bynF := fs.String("byn", "", "filter: events whose .byn path matches (substring)")
	callerF := fs.String("caller", "", "filter: events whose caller matches (substring)")
	scopeF := fs.String("scope", "", "filter: events in a matching project[/env] (substring)")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	if *linesAlias >= 0 {
		*n = *linesAlias
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	client := newClient(dir, scope.Vault)

	filt := func(lines int) ipc.AuditTailReq {
		return ipc.AuditTailReq{Vault: scope.Vault, Lines: lines, Byn: *bynF, Caller: *callerF, Scope: *scopeF}
	}
	var resp ipc.AuditTailResp
	if err := client.Call(ipc.OpAuditTail, filt(*n), &resp); err != nil {
		return handleCallError(err)
	}
	// Snapshot (no -f): JSON mode emits a single array — consistent with
	// `audit view --json` and every other --json command. NDJSON is reserved
	// for the streaming -f path below, where a JSON array can't be left open.
	if !*follow {
		if *jsonOut {
			out, _ := json.MarshalIndent(resp.Events, "", "  ")
			fmt.Println(string(out))
			return exitOK
		}
		if len(resp.Events) == 0 {
			fmt.Fprintln(os.Stderr, "(no audit events recorded yet)")
			return exitOK
		}
		for _, e := range resp.Events {
			fmt.Println(auditLine(e))
		}
		return exitOK
	}

	// Follow (-f): print the initial batch as NDJSON (or text rows), then
	// stream new events the same way.
	for _, e := range resp.Events {
		printAuditEvent(e, *jsonOut)
	}

	// Follow: poll for events newer than the last we've printed. The log
	// is append-only with monotonic timestamps, so a high-water TS dedupes.
	last := maxEventTS(resp.Events)
	for {
		time.Sleep(700 * time.Millisecond)
		var poll ipc.AuditTailResp
		if err := client.Call(ipc.OpAuditTail, filt(256), &poll); err != nil {
			return handleCallError(err)
		}
		var fresh []ipc.AuditEvent
		for _, e := range poll.Events {
			if e.TS > last {
				fresh = append(fresh, e)
			}
		}
		sort.Slice(fresh, func(i, j int) bool { return fresh[i].TS < fresh[j].TS })
		for _, e := range fresh {
			printAuditEvent(e, *jsonOut)
		}
		if t := maxEventTS(fresh); t > last {
			last = t
		}
	}
}

func maxEventTS(events []ipc.AuditEvent) int64 {
	var m int64
	for _, e := range events {
		if e.TS > m {
			m = e.TS
		}
	}
	return m
}

func printAuditEvent(e ipc.AuditEvent, jsonOut bool) {
	if jsonOut {
		b, _ := json.Marshal(e)
		fmt.Println(string(b))
		return
	}
	fmt.Println(auditLine(e))
}

// auditLine renders one event as a human-readable row.
func auditLine(e ipc.AuditEvent) string {
	t := time.Unix(0, e.TS).UTC().Format("2006-01-02 15:04:05Z")
	scopePath := e.Project
	if scopePath == "" {
		scopePath = "-"
	} else if e.Env != "" {
		scopePath += "/" + e.Env
	}
	entryName := e.EntryName
	if entryName == "" {
		entryName = "-"
	}
	// Exec authorizations carry the command + the authorizing .byn instead of
	// an entry name — surface both so a .byn-driven injection is traceable.
	if e.Command != "" {
		entryName = e.Command
	}
	line := fmt.Sprintf("#%-6d %s  %-14s  %-20s  %-20s  %-9s  %s",
		e.Index, t, e.Op, scopePath, entryName, e.Outcome, auditCaller(e))
	if e.BynPath != "" {
		line += "  via " + e.BynPath
	}
	return line
}

// auditCaller renders the "who" of an audit event for forensics, e.g.
// "portal:byn(uid 501)" or "socket:byn(pid 9123, uid 501)←node".
func auditCaller(e ipc.AuditEvent) string {
	surface := e.CallerSurface
	if surface == "" {
		surface = "-"
	}
	out := surface
	if e.CallerComm != "" {
		out += ":" + e.CallerComm
	}
	var det []string
	if e.CallerPID != 0 {
		det = append(det, fmt.Sprintf("pid %d", e.CallerPID))
	}
	if e.CallerUID != 0 {
		det = append(det, fmt.Sprintf("uid %d", e.CallerUID))
	}
	if len(det) > 0 {
		out += "(" + strings.Join(det, ", ") + ")"
	}
	if e.CallerPComm != "" {
		out += "←" + e.CallerPComm
	}
	return out
}

func runAuditVerify(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	var resp ipc.AuditVerifyResp
	if err := newClient(dir, scope.Vault).Call(ipc.OpAuditVerify,
		ipc.AuditVerifyReq{Vault: scope.Vault}, &resp); err != nil {
		return handleCallError(err)
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		if resp.BadIndex >= 0 {
			return exitDaemonErr
		}
		return exitOK
	}
	if resp.BadIndex < 0 {
		fmt.Printf("audit chain intact — %d events verified\n", resp.Total)
		return exitOK
	}
	fmt.Fprintf(os.Stderr, "%s audit chain BROKEN at event #%d (of %d)\n",
		boldRed("FAIL:"), resp.BadIndex, resp.Total)
	fmt.Fprintln(os.Stderr, "  someone or something modified or truncated the log on disk")
	fmt.Fprintln(os.Stderr, "  inspect ~/.byn/audit/<vault>/*.log and treat the vault as compromised")
	return exitDaemonErr
}

// runAuditReseal acknowledges a chain break by appending a signed bridge marker.
// It shows the break, captures a reason, confirms, then sends OpAuditReseal. The
// vault must be unlocked (the daemon enforces this).
func runAuditReseal(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("audit reseal", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	reason := fs.String("reason", "", "why the chain broke (recorded in the marker)")
	assumeYes := fs.Bool("yes", false, "skip the confirmation prompt (requires --reason)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	client := newClient(dir, scope.Vault)

	// Show what would be acknowledged before doing anything.
	var ver ipc.AuditVerifyResp
	if err := client.Call(ipc.OpAuditVerify, ipc.AuditVerifyReq{Vault: scope.Vault}, &ver); err != nil {
		return handleCallError(err)
	}
	if ver.BadIndex < 0 {
		fmt.Printf("audit chain intact — nothing to reseal (%d events)\n", ver.Total)
		return exitOK
	}
	fmt.Fprintf(os.Stderr, "%s audit chain broken at event #%d (of %d).\n",
		boldRed("Break:"), ver.BadIndex, ver.Total)
	fmt.Fprintln(os.Stderr, "Reseal appends a SIGNED marker that ACKNOWLEDGES this discontinuity — it never")
	fmt.Fprintln(os.Stderr, "rewrites or erases anything. The original hashes stay on disk; the marker records")
	fmt.Fprintln(os.Stderr, "who, when, and why. Afterwards `byn audit verify` and `byn doctor` read it as intact.")

	r := strings.TrimSpace(*reason)
	if *assumeYes {
		if r == "" {
			fmt.Fprintln(os.Stderr, "Error: --reason is required with --yes.")
			return exitErr
		}
	} else {
		if r == "" {
			r = strings.TrimSpace(promptLine(os.Stdin, os.Stderr, `Reason (e.g. "daemon restart during testing"): `))
			if r == "" {
				fmt.Fprintln(os.Stderr, "Error: a reason is required to reseal.")
				return exitErr
			}
		}
		if !confirmReseal(os.Stdin, os.Stderr) {
			fmt.Fprintln(os.Stderr, "Aborted.")
			return exitErr
		}
	}

	var resp ipc.AuditResealResp
	if err := client.Call(ipc.OpAuditReseal, ipc.AuditResealReq{Vault: scope.Vault, Reason: r}, &resp); err != nil {
		return handleCallError(err)
	}
	if resp.NoBreak {
		fmt.Println("audit chain already intact — nothing to reseal")
		return exitOK
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		return exitOK
	}
	fmt.Printf("Resealed — acknowledged the break at event #%d.\n", resp.BrokenIndex)
	fmt.Printf("  reason: %s\n", resp.Reason)
	fmt.Printf("  by:     %s\n", resp.By)
	fmt.Println("`byn audit verify` (and `byn doctor`) now read the chain as intact.")
	return exitOK
}

// promptLine writes prompt to out and reads one line from in.
func promptLine(in io.Reader, out io.Writer, prompt string) string {
	_, _ = fmt.Fprint(out, prompt)
	sc := bufio.NewScanner(in)
	if !sc.Scan() {
		return ""
	}
	return sc.Text()
}

// confirmReseal asks for an explicit "yes".
func confirmReseal(in io.Reader, out io.Writer) bool {
	_, _ = fmt.Fprint(out, "Reseal now? Type "+bold("yes")+" to confirm: ")
	sc := bufio.NewScanner(in)
	if !sc.Scan() {
		return false
	}
	return strings.TrimSpace(sc.Text()) == "yes"
}

func printAuditUsage(w *os.File) {
	_, _ = fmt.Fprintln(w, `byn audit — read and verify the per-vault audit log

Usage:
  byn audit view [--lines N] [--json]   Snapshot the last N events (default 50)
  byn audit tail [-n N] [-f] [--json]   Like tail(1): last N (default 10);
                                        -f follows new events in realtime
  byn audit verify [--json]             Re-walk the HMAC chain end-to-end
  byn audit reseal [--reason R] [--yes] Acknowledge a chain break with a signed
                                        marker (vault must be unlocked)`)
}
