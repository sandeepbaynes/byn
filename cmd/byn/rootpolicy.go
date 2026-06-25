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

	"github.com/sandeepbaynes/byn/internal/privsep"
)

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
				"    Run \"byn start\" as yourself; if it's down, \"sudo byn restart\".\n",
				boldRed("Error:"))
			return true
		}
	case classRootWhenProvisioned:
		if euid != 0 && provisionedFn() {
			_, _ = fmt.Fprintf(w, "%s byn %s manages the _byn system daemon and needs root. Run:\n    sudo byn %s\n",
				boldRed("Error:"), cmd, cmd)
			return true
		}
	}
	return false
}

// cliProvisioned reports whether byn is privsep-provisioned (the _byn-exec
// service user exists) — i.e. the daemon runs as _byn and service-management
// commands need root. Daemon-independent: works while the daemon is down.
func cliProvisioned() bool {
	s, err := privsep.LookupState()
	return err == nil && s.Provisioned
}
