// `byn setup` — the keystone provisioning command for privilege separation.
//
//	byn setup                provision: create _byn/_byn-exec, install the spawn
//	                         helper + system service, relocate any legacy ~/.byn,
//	                         record the owner UID (idempotent)
//	byn setup --uninstall    reverse it: uninstall the service, remove the helper
//	                         + owner record (LEAVES the vault by default)
//	byn setup --uninstall --purge   ALSO remove the system data dir (the vault)
//
// All of these are root-required. The orchestration logic lives in
// internal/setup (composing internal/privsep + internal/migrate + internal/
// paths behind injected funcs); this file is a thin wrapper that does the root
// check, builds the production deps, routes, confirms a purge, and prints.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sandeepbaynes/byn/internal/migrate"
	"github.com/sandeepbaynes/byn/internal/paths"
	"github.com/sandeepbaynes/byn/internal/privsep"
	"github.com/sandeepbaynes/byn/internal/setup"
)

// runSetup is the entry point wired into main's command switch.
func runSetup(args []string) int {
	return runSetupWith(args, os.Geteuid, os.Stdin, os.Stdout, os.Stderr)
}

// runSetupWith is the testable core: it parses flags, enforces root, and routes
// to provision vs teardown. The root check + the orchestration deps are the only
// production-touching parts; everything below routes into internal/setup, whose
// side effects are themselves injected and unit-tested without root.
func runSetupWith(args []string, euid func() int, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	uninstall := fs.Bool("uninstall", false, "reverse a previous setup (uninstall the service + helper; keeps the vault)")
	purge := fs.Bool("purge", false, "with --uninstall, ALSO remove the system data dir (the vault) — destructive")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "%s byn setup takes no positional arguments\n", boldRed("Error:"))
		return exitErr
	}
	if *purge && !*uninstall {
		_, _ = fmt.Fprintf(stderr, "%s --purge is only valid with --uninstall\n", boldRed("Error:"))
		_, _ = fmt.Fprintln(stderr, yellow("Run:")+"   "+cyan("sudo byn setup --uninstall --purge"))
		return exitErr
	}

	if euid() != 0 {
		_, _ = fmt.Fprintln(stderr, boldRed("Error:")+" byn setup must run as root")
		hint := "sudo byn setup"
		if *uninstall {
			hint = "sudo byn setup --uninstall"
			if *purge {
				hint += " --purge"
			}
		}
		_, _ = fmt.Fprintln(stderr, yellow("Run:")+" "+cyan(hint))
		return exitErr
	}

	if *uninstall {
		return runTeardown(*purge, stdin, stdout, stderr)
	}
	return runProvision(stdout, stderr)
}

// runProvision builds the production provisioning deps and runs the full setup.
func runProvision(stdout, stderr io.Writer) int {
	deps, err := defaultProvisionDeps()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	res, err := setup.Provision(deps)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	_, _ = fmt.Fprintf(stdout, "byn provisioned: daemon runs as %s, owner UID %d allowlisted\n",
		privsep.DaemonUser, res.OwnerUID)
	if res.Migrated {
		_, _ = fmt.Fprintf(stdout, "relocated legacy %s -> %s (trust + passkeys preserved)\n",
			res.LegacyDir, res.SystemDir)
	}
	_, _ = fmt.Fprintln(stdout, "")
	_, _ = fmt.Fprintln(stdout, "Run byn as your normal user (NOT sudo) — only "+cyan("byn setup")+" needs root.")
	_, _ = fmt.Fprintln(stdout, "Enable privilege separation: set "+cyan("[security] privsep = true")+
		" via the portal ("+cyan("byn web")+" → Settings) or by editing "+
		cyan(filepath.Join(res.SystemDir, "config"))+" as root, then restart the daemon service.")
	printMacOSFDANote(stdout)
	return exitOK
}

// printMacOSFDANote warns, on macOS only, that the daemon (running as _byn under
// launchd) cannot read .byn files in TCC-protected folders without Full Disk
// Access — and that keeping projects elsewhere avoids the issue entirely. No-op
// on other platforms (no TCC).
func printMacOSFDANote(stdout io.Writer) {
	if runtime.GOOS != "darwin" {
		return
	}
	_, _ = fmt.Fprintln(stdout, "")
	_, _ = fmt.Fprintln(stdout, "macOS note: the daemon runs as "+cyan(privsep.DaemonUser)+
		" and macOS privacy protection (TCC) blocks it from reading .byn files under "+
		cyan("~/Documents")+", "+cyan("~/Desktop")+", "+cyan("~/Downloads")+" or iCloud Drive.")
	_, _ = fmt.Fprintln(stdout, "  • Easiest: keep byn projects OUTSIDE those folders (e.g. "+cyan("~/code")+
		") — then nothing else is needed.")
	_, _ = fmt.Fprintln(stdout, "  • Otherwise: grant "+bold("Full Disk Access")+" to the byn binary in "+
		cyan("System Settings > Privacy & Security > Full Disk Access")+", then restart the daemon.")
}

// runTeardown confirms a purge (loud) then reverses a previous setup.
func runTeardown(purge bool, stdin io.Reader, stdout, stderr io.Writer) int {
	if purge && !confirmPurge(stdin, stdout) {
		_, _ = fmt.Fprintln(stderr, yellow("Aborted.")+" The vault was NOT removed.")
		return exitErr
	}
	res, err := setup.Teardown(defaultTeardownDeps(), purge)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	_, _ = fmt.Fprintln(stdout, "byn unprovisioned: system service + spawn helper + owner record removed")
	if res.Purged {
		_, _ = fmt.Fprintf(stdout, "purged the system data dir %s (the vault is gone)\n", res.SystemDir)
	} else {
		_, _ = fmt.Fprintln(stdout, "the vault under the system data dir was left intact (use "+
			cyan("--purge")+" to also remove it)")
	}
	return exitOK
}

// confirmPurge requires the user to type "yes" before the vault is destroyed.
// A non-interactive stdin (no "yes") aborts safely — the vault is never removed
// without explicit confirmation.
func confirmPurge(stdin io.Reader, stdout io.Writer) bool {
	_, _ = fmt.Fprintln(stdout, boldRed("DANGER:")+" --purge will PERMANENTLY DELETE the byn vault under "+
		cyan(paths.SystemDataDir())+".")
	_, _ = fmt.Fprintln(stdout, "This destroys all stored secrets. There is no undo.")
	_, _ = fmt.Fprint(stdout, "Type "+bold("yes")+" to confirm: ")
	sc := bufio.NewScanner(stdin)
	if !sc.Scan() {
		return false
	}
	return strings.TrimSpace(sc.Text()) == "yes"
}

// defaultProvisionDeps builds the production [setup.Deps] — the real syscalls,
// privsep + migrate primitives, and the prebuilt-helper lookup. A missing
// prebuilt helper is the one pre-flight error surfaced here (the rest are
// internal/setup's domain).
func defaultProvisionDeps() (setup.Deps, error) {
	srcHelper, err := prebuiltHelperPath()
	if err != nil {
		return setup.Deps{}, err
	}
	run := privilegedRunner()
	systemDir := paths.SystemDataDir()
	ownerRecordPath := paths.OwnerRecordIn(systemDir)

	return setup.Deps{
		SudoUID: func() (int, bool) { return resolveSudoUID(os.Getenv) },
		LegacyDir: func() (string, bool, error) {
			return resolveLegacyDir(os.Getenv, user.Lookup, os.Stat)
		},
		SystemDataDir:   paths.SystemDataDir,
		OwnerRecordPath: func() string { return ownerRecordPath },
		DaemonUser:      privsep.LookupDaemonUser,
		InstallSpawnHelper: func() error {
			return privsep.Setup(run, srcHelper, privsep.HelperDestPath(), privsep.HelperConfigPath())
		},
		InstallService: func() error {
			exe, eerr := os.Executable()
			if eerr != nil {
				return fmt.Errorf("determine byn executable path: %w", eerr)
			}
			return privsep.InstallService(run, exe)
		},
		Relocate: func(legacyDir, sysDir string, uid, gid int) error {
			return migrate.Relocate(legacyDir, sysDir, migrate.Options{UID: uid, GID: gid})
		},
		WriteOwnerRecord: privsep.WriteOwnerRecord,
		Verify:           verifyProvisioned,
	}, nil
}

// defaultTeardownDeps builds the production [setup.TeardownDeps].
func defaultTeardownDeps() setup.TeardownDeps {
	run := privilegedRunner()
	return setup.TeardownDeps{
		UninstallService: func() error { return privsep.UninstallService(run) },
		RemoveSpawnHelper: func() error {
			for _, p := range []string{privsep.HelperDestPath(), privsep.HelperConfigPath()} {
				if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("remove %s: %w", p, err)
				}
			}
			return nil
		},
		RemoveOwnerRecord: func() error {
			p := paths.OwnerRecordIn(paths.SystemDataDir())
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove %s: %w", p, err)
			}
			return nil
		},
		SystemDataDir: paths.SystemDataDir,
		PurgeDataDir: func(systemDir string) error {
			if err := os.RemoveAll(systemDir); err != nil {
				return fmt.Errorf("remove %s: %w", systemDir, err)
			}
			return nil
		},
	}
}

// verifyProvisioned is the lightweight post-conditions check: the system data
// dir exists and the owner record is readable and records the expected UID. It
// deliberately does NOT start the daemon as _byn — that is fragile mid-setup
// (the service may still be coming up) and the post-conditions here are
// sufficient evidence the install is sound.
//
// The _byn ownership of the system data dir is checked only as a NON-FATAL
// warning: on a fresh install the dir is created root-owned by the helper-
// install step, and on Linux systemd's StateDirectory=byn only re-owns it to
// _byn:_byn when the unit actually starts — which races with this verify. So a
// not-yet-_byn-owned dir at verify time is normal and must not fail setup; a
// relocate, by contrast, has already chowned the tree to _byn. The hard
// post-conditions are the dir existing and the owner record being correct.
func verifyProvisioned(systemDir, ownerRecordPath string, ownerUID, daemonUID, daemonGID int) error {
	fi, err := os.Stat(systemDir)
	if err != nil {
		return fmt.Errorf("system data dir %s missing: %w", systemDir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("system data dir %s is not a directory", systemDir)
	}
	if oerr := verifyOwnedBy(fi, daemonUID, daemonGID); oerr != nil {
		// Non-fatal: the service may not have re-owned StateDirectory yet.
		fmt.Fprintf(os.Stderr, "byn setup: note — %s not yet owned by %s (%v); "+
			"it is re-owned when the daemon service starts\n", systemDir, privsep.DaemonUser, oerr)
	}
	recorded, err := privsep.ReadOwnerRecord(ownerRecordPath)
	if err != nil {
		return fmt.Errorf("owner record unreadable: %w", err)
	}
	if recorded != ownerUID {
		return fmt.Errorf("owner record holds UID %d, expected %d", recorded, ownerUID)
	}
	return nil
}

// prebuiltHelperPath locates the prebuilt byn-exec-helper next to the running
// byn binary and verifies it exists (the one pre-flight error worth surfacing
// before any side effects).
func prebuiltHelperPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("could not determine byn executable path: %w", err)
	}
	src := filepath.Join(filepath.Dir(exe), "byn-exec-helper")
	if _, serr := os.Stat(src); os.IsNotExist(serr) {
		return "", fmt.Errorf("prebuilt byn-exec-helper not found next to byn (%s); reinstall byn", src)
	}
	return src, nil
}

// privilegedRunner returns the production command runner: it execs fixed
// commands supplied by internal/privsep (never user input). It CAPTURES each
// command's output and discards it on success — byn reports its own result, so
// raw launchctl/systemctl/dscl chatter (the `launchctl print` settle-poll's
// service blob, "Bad request", "Could not find service") never reaches the
// terminal — and surfaces the captured output only when a command actually
// fails (so a real "Bootstrap failed: 5: Input/output error" is still shown).
func privilegedRunner() func(string, ...string) error {
	return func(cmd string, runArgs ...string) error {
		c := exec.Command(cmd, runArgs...) //nolint:gosec // commands are fixed strings from internal/privsep, not user input
		out, err := c.CombinedOutput()
		if err == nil {
			return nil
		}
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return fmt.Errorf("%s: %w: %s", cmd, err, msg)
		}
		return fmt.Errorf("%s: %w", cmd, err)
	}
}
