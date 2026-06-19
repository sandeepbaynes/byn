package main

// daemon_privsep.go makes the daemon-control commands privsep-aware. Under
// privilege separation the daemon is the _byn launchd/systemd service: it must
// never be spawned as the owner (start), and stop/restart must act on the
// service (a plain SIGTERM is futile — KeepAlive respawns it). reload still
// works via SIGHUP (the process re-reads config without exiting), root-gated by
// the root-policy guard.

import (
	"fmt"
	"os"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

// Seams for the privsep-aware branches, overridable in tests.
var (
	daemonProvisioned = cliProvisioned
	daemonReachableFn = daemonReachable
	restartServiceFn  = func() error { return privsep.RestartService(execRunner) }
	stopServiceFn     = func() error { return privsep.StopService(execRunner) }
)

// startProvisionedDelegate handles `byn start` (run as the owner) when byn is
// privsep-provisioned: report whether the _byn service is up, and point at the
// root path to bring it up — never spawn a daemon as the owner.
func startProvisionedDelegate(dir string) int {
	if daemonReachableFn(dir) {
		fmt.Println("byn daemon is already running (the _byn launchd service auto-starts it).")
		return exitOK
	}
	fmt.Fprintln(os.Stderr, "The byn daemon runs as the _byn service (auto-starts on boot/crash); it appears down.")
	fmt.Fprintln(os.Stderr, "Bring it up with:")
	fmt.Fprintln(os.Stderr, "    sudo byn restart            (or: sudo byn doctor --repair)")
	return exitErr
}
