package main

// rootpolicy.go enforces WHO each top-level command must run as, before the
// command does any work. It replaces cryptic downstream failures (e.g. the
// daemon's "this peer may only redeem exec tokens" when a root caller hits the
// owner-only socket, or a "socket not ready" when `sudo byn start`'s detached
// child refuses root into the log) with one early, actionable message.
//
// Under privsep the daemon runs as the _byn service user: the owner-UID socket
// only ever accepts you, so owner commands run as root were always wrong; and
// service-management commands act on the _byn system daemon, which only root can
// signal. `byn setup`/`migrate`/`daemon`/`doctor` self-manage their own root
// logic (setup/migrate already require root; doctor's --repair needs root while
// plain diagnose runs as anyone) and are left to the guard's classSelfChecks.

import (
	"fmt"
	"io"
	"os"

	"github.com/sandeepbaynes/byn/internal/paths"
	"github.com/sandeepbaynes/byn/internal/privsep"
)

// cliProvisioned reports whether byn is privsep-provisioned on this machine.
//
// Accounts are not a service. `byn setup --uninstall` removes the unit, the
// spawn helper and the owner record, and deliberately leaves the _byn accounts
// behind — they may still own files. Judging provisioning by the accounts alone
// therefore left a machine claiming to be provisioned with nothing installed,
// and that claim was a dead end: `byn start` refused to run a user daemon and
// sent the caller to `sudo byn restart` for a unit that no longer existed, so
// byn could not be started at all. That is the state a `go install` lands in on
// any machine byn has ever been set up on.
//
// So this asks whether setup actually left anything behind, not whether a user
// exists.
func cliProvisioned() bool {
	if forcedUnprovisioned() {
		return false
	}
	s, err := privsep.LookupState()
	if err != nil || !s.Provisioned {
		return false
	}
	return privsepArtifactsPresent()
}

// privsepInstall describes how far a privsep install actually got, because the
// three states need three different answers and byn was giving one.
type privsepInstall int

const (
	// privsepNone: nothing installed. byn runs its own daemon as you.
	privsepNone privsepInstall = iota
	// privsepService: the spawn helper is installed, so the daemon is the
	// system service and only root manages it.
	privsepService
	// privsepDataOnly: a provisioned data tree with no service to serve it.
	// This is what an uninstall leaves when the vault is kept, and what a
	// `go install` lands in on a machine byn has ever been set up on. It is
	// neither startable by you (the data belongs to _byn) nor restartable as a
	// service (there is no unit) — the fix is to install the service again.
	privsepDataOnly
)

// privsepInstallStateFn is the seam tests stub; the real one reads the disk.
var privsepInstallStateFn = privsepInstallState

// privsepInstallState reports which of those three a machine is in.
func privsepInstallState() privsepInstall {
	if fi, err := os.Stat(privsep.HelperDestPath()); err == nil && !fi.IsDir() {
		return privsepService
	}
	if fi, err := os.Stat(paths.SystemDataDir()); err == nil && fi.IsDir() {
		return privsepDataOnly
	}
	return privsepNone
}

// privsepArtifactsPresent reports whether setup left anything behind at all.
func privsepArtifactsPresent() bool { return privsepInstallStateFn() != privsepNone }

// rootClass is how a top-level command relates to the root/owner identity split.
type rootClass int

const (
	classNeutral             rootClass = iota // version/help — no policy
	classOwner                                // must run as you; refuse under sudo/root
	classRootWhenProvisioned                  // acts on the _byn service; needs root once provisioned
	classStart                                // refuse root; the owner path is handled in runDaemonStart
	classSelfChecks                           // setup/migrate/daemon/doctor — self-manage their own root logic
)

// cmdRootClass classifies a top-level command for the root-policy guard.
func cmdRootClass(cmd string) rootClass {
	switch cmd {
	case "status", "unlock", "lock", "passwd", "password", "put", "get", "cat",
		"edit", "view", "list", "ls", "delete", "rm", "rename", "mv", "exec",
		"vault", "project", "env", "import", "export", "audit", "trust",
		"untrust", "web", "ui", "init", "config-auth":
		return classOwner
	case "restart", "reload", "stop":
		return classRootWhenProvisioned
	case "start":
		return classStart
	case "setup", "uninstall", "migrate", "daemon", "doctor":
		return classSelfChecks
	default:
		return classNeutral
	}
}

// enforceRootPolicy writes an actionable message and returns true to refuse the
// command when it is run as the wrong identity. provisionedFn is evaluated
// lazily — only for service-management commands — to avoid a passwd lookup on
// the common owner-command path.
func enforceRootPolicy(cmd string, euid int, provisionedFn func() bool, w io.Writer) bool {
	switch cmdRootClass(cmd) {
	case classOwner:
		if euid == 0 {
			_, _ = fmt.Fprintf(w, "%s byn %s runs as you, not root. Re-run without sudo:\n    byn %s …\n",
				boldRed("Error:"), cmd, cmd)
			return true
		}
	case classStart:
		if euid == 0 {
			_, _ = fmt.Fprintf(w, "%s don't start byn as root — the daemon runs as the _byn service.\n"+
				"    Run \"byn start\" as yourself; if it's down, \"byn restart\" (it asks for your password).\n",
				boldRed("Error:"))
			return true
		}
	case classRootWhenProvisioned:
		provisioned := provisionedFn()
		if euid != 0 && provisioned {
			// Reached only when byn could not ask for the password itself —
			// no terminal, no sudo on PATH, or a sudo that did not elevate.
			_, _ = fmt.Fprintf(w, "%s byn %s manages the _byn system daemon and needs root. Run:\n    %s\n",
				boldRed("Error:"), cmd, sudoByn(cmd))
			return true
		}
		// Root on an UNPROVISIONED machine: there is no _byn service to manage,
		// only your own daemon — and root cannot run it.
		//
		// This has to refuse HERE, before dispatch, because restart is
		// stop-then-start: the stop succeeds and the start is then refused for
		// being root, so the machine ends up with no daemon and an error about a
		// privsep install it does not have. `start` has always refused root up
		// front (classStart above); these three did not, and the asymmetry is the
		// whole bug — the command that takes a daemon down was the one allowed to
		// get that far.
		if euid == 0 && !provisioned {
			_, _ = fmt.Fprintf(w, "%s byn %s runs as you here — byn is not provisioned, so there is no "+
				"_byn service to manage, just your own daemon (which cannot run as root).\n"+
				"    Re-run without sudo:\n        byn %s\n"+
				"    To run the daemon as the _byn service instead: %s\n",
				boldRed("Error:"), cmd, cmd, sudoByn("setup"))
			return true
		}
	}
	return false
}

// cliProvisioned reports whether byn is privsep-provisioned (the _byn-exec
// service user exists) — i.e. the daemon runs as _byn and service-management
// commands need root. Daemon-independent: works while the daemon is down.
