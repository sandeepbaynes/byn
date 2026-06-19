// `byn doctor` — health battery. Runs daemon-INDEPENDENT provisioning/health
// checks (which work while the daemon is DOWN — exactly when you need them) plus,
// when the daemon is reachable, the daemon-side checks (vault enumeration,
// fingerprint, schema, audit chain). `byn doctor --repair` (root) heals the
// common broken state. Exit code is non-zero if any check failed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// doctorEnv builds the local-check environment for a data dir. A package var so
// tests can inject a controlled environment instead of probing the real machine.
var doctorEnv = productionHealEnv

func runDoctor(args []string, _ cliScope) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "output as JSON")
	repair := fs.Bool("repair", false, "apply fixes for failing provisioning/health checks (requires root)")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	env := doctorEnv(dir)

	// --repair applies the safe fixes (chown the data dir back to _byn, reload the
	// service, clear a stale socket) — the recovery a user would otherwise run by
	// hand. It needs root; without --repair, doctor only diagnoses (dry-run).
	if *repair {
		if os.Geteuid() != 0 {
			fmt.Fprintf(os.Stderr, "%s byn doctor --repair needs root. Run:\n    sudo byn doctor --repair\n", boldRed("Error:"))
			return exitErr
		}
		actions := repairHeal(env, execRunner)
		if len(actions) == 0 {
			fmt.Println("repair: nothing to do")
		}
		for _, a := range actions {
			fmt.Printf("repair: %s\n", a)
		}
		fmt.Println()
	}

	// Local (daemon-independent) checks — work even when the daemon is down.
	local := diagnoseHeal(env)

	// Daemon-side checks only when reachable; a down daemon is already reported by
	// the local "daemon running" check, so we never hard-fail when it is down.
	var dResp ipc.DoctorResp
	daemonChecked := false
	if env.daemonUp() {
		if cerr := newClient(dir, "").Call(ipc.OpDoctor, ipc.DoctorReq{}, &dResp); cerr == nil {
			daemonChecked = true
		}
	}

	if *jsonOut {
		payload := struct {
			Local  []healCheck     `json:"local"`
			Daemon *ipc.DoctorResp `json:"daemon,omitempty"`
		}{Local: local}
		if daemonChecked {
			payload.Daemon = &dResp
		}
		out, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Println(string(out))
		return healExitCode(local, daemonChecked, dResp)
	}

	fmt.Println("Provisioning & health:")
	for _, c := range local {
		printHealCheck(c)
	}
	if daemonChecked {
		fmt.Println("\nDaemon-side checks:")
		for _, c := range dResp.Checks {
			printDaemonCheck(c)
		}
	}
	return healExitCode(local, daemonChecked, dResp)
}

// printHealCheck renders a local provisioning/health check with its fix hint.
func printHealCheck(c healCheck) {
	marker := " FAIL "
	if c.OK {
		marker = "  OK  "
	}
	line := fmt.Sprintf("[%s] %s", marker, c.Name)
	if c.Detail != "" {
		line += "  — " + c.Detail
	}
	if !c.OK && c.Fix != "" {
		line += "  → " + c.Fix
	}
	fmt.Println(line)
}

// printDaemonCheck renders a daemon-side OpDoctor check.
func printDaemonCheck(c ipc.DoctorCheck) {
	marker := " ?     "
	switch c.Severity {
	case "ok":
		marker = "  OK   "
	case "warn":
		marker = " WARN  "
	case "fail":
		marker = " FAIL  "
	}
	if c.Detail != "" {
		fmt.Printf("[%s] %-40s  %s\n", marker, c.Name, c.Detail)
	} else {
		fmt.Printf("[%s] %s\n", marker, c.Name)
	}
}

// healExitCode is non-zero if any local check failed, or (when the daemon was
// reachable) any daemon-side check failed.
func healExitCode(local []healCheck, daemonChecked bool, d ipc.DoctorResp) int {
	for _, c := range local {
		if !c.OK {
			return exitErr
		}
	}
	if daemonChecked {
		return doctorExitCode(d)
	}
	return exitOK
}

func doctorExitCode(r ipc.DoctorResp) int {
	for _, c := range r.Checks {
		if c.Severity == "fail" {
			return exitErr
		}
	}
	return exitOK
}
