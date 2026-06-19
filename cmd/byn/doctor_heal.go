package main

// doctor_heal.go adds the daemon-INDEPENDENT half of `byn doctor`: provisioning
// and health checks that work while the daemon is down (exactly when you need
// them), plus `--repair` to heal the common broken state — a stale launchd
// registration, root-owned files left by a `sudo byn start`, or a stale socket.
// It mirrors the recovery a user would otherwise run by hand (launchctl
// bootout/bootstrap + chown -R _byn + rm stale socket).

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/sandeepbaynes/byn/internal/paths"
	"github.com/sandeepbaynes/byn/internal/privsep"
)

// healCheck is one daemon-independent provisioning/health check.
type healCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// healEnv injects the OS/probe seams so the local checks + repair are
// unit-testable without root, launchd, or a live daemon.
type healEnv struct {
	provisioned func() bool                   // privsep provisioned (LookupState)
	exists      func(path string) bool        // os.Stat succeeds
	fileUID     func(path string) (int, bool) // owner uid of a path
	bynUID      func() (int, bool)            // uid of the _byn service user
	daemonUp    func() bool                   // daemon socket reachable
	dataDir     string
	helperPath  string // installed setuid spawn helper
}

func (e healEnv) socketPath() string { return filepath.Join(e.dataDir, "daemon.sock") }

// diagnoseHeal runs the daemon-independent provisioning/health checks. The
// "privsep provisioned" check short-circuits the rest: nothing else is
// meaningful (or fixable) until setup has run.
func diagnoseHeal(e healEnv) []healCheck {
	if !e.provisioned() {
		// privsep is OPT-IN: not being provisioned is a valid (default) state, not
		// a failure. Report it informationally (OK) and run no privsep-specific
		// checks. The daemon-side checks still run separately when the daemon (here
		// an owner daemon) is reachable.
		return []healCheck{{Name: "privilege separation", OK: true, Detail: "not provisioned (opt-in) — enable with: sudo byn setup"}}
	}
	cs := []healCheck{{Name: "privilege separation", OK: true, Detail: "provisioned (daemon runs as _byn)"}}
	cs = append(cs, healCheck{Name: "spawn helper installed", OK: e.exists(e.helperPath), Detail: e.helperPath, Fix: "run: sudo byn setup"})

	up := e.daemonUp()
	cs = append(cs, healCheck{Name: "daemon running", OK: up, Fix: "run: sudo byn restart  (or sudo byn doctor --repair)"})

	if bynUID, ok := e.bynUID(); ok {
		dirUID, okD := e.fileUID(e.dataDir)
		owned := okD && dirUID == bynUID
		detail := ""
		if okD && !owned {
			detail = fmt.Sprintf("owned by uid %d, expected %s (uid %d) — a sudo-run left root-owned files", dirUID, privsep.DaemonUser, bynUID)
		}
		cs = append(cs, healCheck{Name: "data dir owned by " + privsep.DaemonUser, OK: owned, Detail: detail, Fix: "run: sudo byn doctor --repair"})
	}

	if !up && e.exists(e.socketPath()) {
		cs = append(cs, healCheck{Name: "no stale socket", OK: false, Detail: "socket present but the daemon is down", Fix: "run: sudo byn doctor --repair"})
	}
	return cs
}

// repairHeal applies the safe fixes (chown the data dir back to _byn, then
// reload the launchd/systemd service which also clears a stale socket). Requires
// root; run is the command runner. Returns the actions taken, in order.
func repairHeal(e healEnv, run func(string, ...string) error) []string {
	var done []string
	if err := run("chown", "-R", privsep.DaemonUser+":"+privsep.DaemonUser, e.dataDir); err == nil {
		done = append(done, "restored "+privsep.DaemonUser+" ownership of "+e.dataDir)
	}
	if err := privsep.RestartService(run); err == nil {
		done = append(done, "reloaded the "+privsep.DaemonUser+" service")
	}
	return done
}

// productionHealEnv wires the real OS probes for the data dir at dir.
func productionHealEnv(dir string) healEnv {
	return healEnv{
		provisioned: cliProvisioned,
		exists:      func(p string) bool { _, err := os.Stat(p); return err == nil },
		fileUID:     fileUID,
		bynUID:      func() (int, bool) { return lookupUID(privsep.DaemonUser) },
		daemonUp:    func() bool { return daemonReachable(dir) },
		dataDir:     dir,
		helperPath:  privsep.HelperDestPath(),
	}
}

// fileUID returns the owning uid of path.
func fileUID(path string) (int, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// lookupUID resolves a username to its uid.
func lookupUID(name string) (int, bool) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, false
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, false
	}
	return uid, true
}

// daemonReachable reports whether the daemon socket accepts a connection.
func daemonReachable(dir string) bool {
	sock, err := paths.ActiveSocketPath(dir)
	if err != nil {
		return false
	}
	c, err := net.DialTimeout("unix", sock, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// execRunner runs a fixed-shape recovery command (chown / launchctl / systemctl).
func execRunner(name string, args ...string) error {
	return exec.Command(name, args...).Run() // #nosec G204 -- fixed-shape recovery commands, root-gated
}
