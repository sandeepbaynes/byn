package main

import "fmt"

// staleDaemonNote reports that the running daemon is not the byn that was
// installed, and returns "" when there is nothing to say.
//
// Installing a new byn does not replace the running daemon — the old process
// keeps serving from the binary it started with until the service is actually
// restarted. Nothing said so: `byn status` printed the daemon's version plainly
// next to a CLI of a different one, and a restart that silently did not happen
// looked exactly like one that did. Fixes then appeared not to work, which is a
// far more expensive kind of confusion than a stale version.
//
// Only ever a note. A version skew is normal while an upgrade is in flight, and
// the daemon it describes is working.
func staleDaemonNote(daemonVersion, cliVersion string) string {
	if daemonVersion == "" || cliVersion == "" || daemonVersion == cliVersion {
		return ""
	}
	return fmt.Sprintf("%s    the daemon is running %s but this byn is %s — restart to pick up the installed one:\n         %s",
		boldYellow("stale:"), daemonVersion, cliVersion, cyan(restartDaemonCommand()))
}

// restartDaemonCommand is the command that actually replaces the running
// daemon. Under privsep that needs root, and `byn restart` asks for the
// password itself, so it is the same command either way.
func restartDaemonCommand() string {
	return "byn restart"
}
