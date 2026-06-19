//go:build darwin

package privsep

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/sandeepbaynes/byn/internal/paths"
)

// svcSleep is the delay used while waiting for launchd to settle between bootout
// and bootstrap. A package var so tests can stub it to a no-op (no real sleeps).
var svcSleep = time.Sleep

const (
	// serviceSettlePolls × serviceSettleInterval bound how long we wait for a
	// booted-out label to fully disappear before bootstrapping it again.
	serviceSettlePolls    = 6
	serviceSettleInterval = 500 * time.Millisecond
	// bootstrapRetryDelay is the pause before the single bootstrap retry.
	bootstrapRetryDelay = 700 * time.Millisecond
)

// launchDaemonLabel is the reverse-DNS bundle id of the byn system LaunchDaemon.
// It is a documented literal matching the existing user-LaunchAgent id
// (cmd/byn/cmd_daemon_install.go launchdLabel) so an upgrade from the old
// per-user agent to this system daemon reuses one stable identity. The label
// also names the on-disk plist (launchDaemonPlistPath).
const launchDaemonLabel = "com.sandeepbaynes.byn"

// launchDaemonPlistPath is the canonical install location of the byn system
// LaunchDaemon plist. /Library/LaunchDaemons is the admin-managed system-wide
// daemon dir (vs ~/Library/LaunchAgents for the per-user agent NU-6 replaces).
// The file is owned root:wheel 0644 by the install step; launchd refuses to load
// a daemon plist that is group/other-writable.
const launchDaemonPlistPath = "/Library/LaunchDaemons/" + launchDaemonLabel + ".plist"

// launchDaemonPlist returns the /Library/LaunchDaemons/com.sandeepbaynes.byn.plist
// content for the byn daemon. execPath is the absolute path to the installed byn
// binary (e.g. /usr/local/bin/byn); ProgramArguments runs `<execPath> daemon
// start --foreground`.
//
// --foreground is load-bearing: launchd IS the supervisor and tracks the spawned
// process, so the daemon must run in the foreground and NOT self-detach. Without
// it, `daemon start` forks a detached daemon and the launchd-tracked process
// exits; KeepAlive then respawns endlessly, each respawn failing the pidfile
// singleton check against the already-detached daemon ("another daemon appears to
// be running").
//
// The daemon runs as the _byn service user (UserName), NOT the human owner — the
// privsep boundary the whole feature exists to create. RunAtLoad + KeepAlive make
// launchd start it at boot and restart it on crash. Its state lives under
// paths.SystemDataDir() (/Library/Application Support/byn), owned _byn:_byn 0700,
// created by `byn setup`/`byn migrate` rather than by launchd.
//
// The output is a property list the install step writes verbatim; it must be
// valid plist XML (asserted in-test with `plutil -lint`).
func launchDaemonPlist(execPath string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>` + launchDaemonLabel + `</string>
  <key>UserName</key>
  <string>` + DaemonUser + `</string>
  <key>ProgramArguments</key>
  <array>
    <string>` + execPath + `</string>
    <string>daemon</string>
    <string>start</string>
    <string>--foreground</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>WorkingDirectory</key>
  <string>` + paths.SystemDataDir() + `</string>
</dict>
</plist>
`
}

// hideServiceAccounts marks the _byn / _byn-exec service accounts hidden so they
// do not appear in the macOS login window or System Settings user list.
// provisionUsers already sets IsHidden when it creates an account; this re-asserts
// it so accounts that already existed (provisionUsers no-op) are hidden too.
// Idempotent: re-creating the IsHidden attribute is a no-op overwrite. All side
// effects go through the injected runner.
func hideServiceAccounts(run runner) error {
	for _, u := range []string{DaemonUser, ExecUser} {
		if err := run("dscl", ".", "-create", "/Users/"+u, "IsHidden", "1"); err != nil {
			return fmt.Errorf("hide %s: %w", u, err)
		}
	}
	return nil
}

// shSingleQuote wraps s in POSIX single quotes so it survives `sh -c` verbatim —
// real newlines, XML double-quotes and all. An embedded single quote is escaped
// with the standard shell idiom (close-quote, backslash-quote, reopen-quote).
// The plist write uses this with printf %s, NOT Go's %q: %q emits a Go string
// literal (backslash-n, backslash-quote) which printf %s writes LITERALLY,
// producing a one-line plist full of backslashes that launchd rejects
// ("Unexpected character at line 1").
func shSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// launchDaemonWriteCmd builds the `sh -c` command that writes plist to path,
// then makes it root:wheel 0644 (launchd refuses a group/other-writable daemon
// plist). The content is single-quoted so its newlines survive intact.
func launchDaemonWriteCmd(plist, path string) string {
	qp := shSingleQuote(path)
	return fmt.Sprintf("printf '%%s' %s > %s && chown root:wheel %s && chmod 0644 %s",
		shSingleQuote(plist), qp, qp, qp)
}

// InstallService provisions the service accounts and installs + loads the byn
// daemon as a system LaunchDaemon. execPath is the absolute path to the installed
// byn binary (the plist's ProgramArguments). All side effects go through the
// injected runner so the sequence is unit-testable without root or launchctl.
//
// Sequence: create _byn/_byn-exec service accounts (reusing provisionUsers)
// → hide them (dscl IsHidden) → write the root:wheel 0644 plist →
// launchctl bootstrap system <plist>.
//
// Account creation reuses provisionUsers from provision_darwin.go (the single
// source of truth for the dscl service-account creation) so the daemon and exec
// accounts are defined in exactly one place.
func InstallService(run runner, execPath string) error {
	if _, err := provisionUsers(osLookup, run, osIDInUse); err != nil {
		return err
	}
	if err := hideServiceAccounts(run); err != nil {
		return err
	}
	plist := launchDaemonPlist(execPath)
	if err := run("sh", "-c", launchDaemonWriteCmd(plist, launchDaemonPlistPath)); err != nil {
		return fmt.Errorf("write LaunchDaemon plist: %w", err)
	}
	// (Re)load the daemon robustly. Hardened against the launchd race that
	// surfaces as "Bootstrap failed: 5: Input/output error" when bootstrap runs
	// before a just-booted-out label has fully torn down, or when a stale
	// socket/pidfile is in the way.
	return reloadDaemonService(run)
}

// reloadDaemonService (re)loads the byn LaunchDaemon idempotently and
// race-free: best-effort bootout any existing instance, WAIT until launchd
// reports the label gone, remove the stale runtime files a crashed/booted-out
// daemon may leave, then bootstrap with one retry on a transient failure. All
// side effects go through the injected runner. Reused by setup, restart, and
// `doctor --repair`.
func reloadDaemonService(run runner) error {
	_ = run("launchctl", "bootout", "system/"+launchDaemonLabel) // best-effort; harmless when not loaded
	waitServiceGone(run)
	removeStaleRuntime(run)
	if err := run("launchctl", "bootstrap", "system", launchDaemonPlistPath); err != nil {
		svcSleep(bootstrapRetryDelay)
		_ = run("launchctl", "bootout", "system/"+launchDaemonLabel)
		waitServiceGone(run)
		if err2 := run("launchctl", "bootstrap", "system", launchDaemonPlistPath); err2 != nil {
			return fmt.Errorf("bootstrap LaunchDaemon: %w", err2)
		}
	}
	return nil
}

// waitServiceGone polls until `launchctl print` reports the label is not loaded
// (a non-zero exit → the runner returns an error), bounded so a stuck service
// never hangs setup.
func waitServiceGone(run runner) {
	for i := 0; i < serviceSettlePolls; i++ {
		if run("launchctl", "print", "system/"+launchDaemonLabel) != nil {
			return // print failed → not loaded → gone
		}
		svcSleep(serviceSettleInterval)
	}
}

// removeStaleRuntime deletes a leftover daemon socket/pidfile that would block a
// fresh bind. Best-effort; the daemon recreates them on start. The filenames
// mirror daemon.SocketFilename / daemon.PIDFilename (not imported here — the
// daemon package depends on privsep, so this dependency must not reverse).
func removeStaleRuntime(run runner) {
	dir := paths.SystemDataDir()
	_ = run("rm", "-f", filepath.Join(dir, "daemon.sock"), filepath.Join(dir, "daemon.pid"))
}

// UninstallService bootouts + removes the byn LaunchDaemon plist. It deliberately
// leaves the _byn/_byn-exec accounts and the vault state under the system data
// dir in place — removing accounts + state is a separate `--purge` concern handled
// by `byn setup --uninstall` (Task 10). All side effects go through the injected
// runner.
//
// Sequence: launchctl bootout system <plist> → remove the plist.
func UninstallService(run runner) error {
	if err := run("launchctl", "bootout", "system", launchDaemonPlistPath); err != nil {
		return fmt.Errorf("bootout LaunchDaemon: %w", err)
	}
	if err := run("rm", "-f", launchDaemonPlistPath); err != nil {
		return fmt.Errorf("remove LaunchDaemon plist: %w", err)
	}
	return nil
}

// RestartService reloads the byn LaunchDaemon via the hardened bootout→wait→
// rm-stale→bootstrap(+retry) path. Exported for `byn restart` and
// `byn doctor --repair`. Requires root. All side effects go through run.
func RestartService(run runner) error { return reloadDaemonService(run) }
