// byn uninstall — cleanly removes the byn installation from this system.
//
//	sudo byn uninstall          remove service + binaries; prompt about the vault
//	sudo byn uninstall --purge  remove everything including the vault without prompting
//
// Must run as root: binaries live in a system path and the service teardown
// requires elevated permissions. The vault question always defaults to KEEP —
// only an explicit "yes" destroys it.
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
	"strings"

	"github.com/sandeepbaynes/byn/internal/paths"
	"github.com/sandeepbaynes/byn/internal/privsep"
	"github.com/sandeepbaynes/byn/internal/setup"
)

func runUninstall(args []string) int {
	return runUninstallWith(args, os.Geteuid, os.Getenv, os.Stdin, os.Stdout, os.Stderr)
}

func runUninstallWith(args []string, euid func() int, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(stderr)
	purge := fs.Bool("purge", false, "also delete the vault and all secrets (no confirmation prompt)")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "%s byn uninstall takes no positional arguments\n", boldRed("Error:"))
		return exitErr
	}

	if euid() != 0 {
		_, _ = fmt.Fprintln(stderr, boldRed("Error:")+" byn uninstall must run as root")
		_, _ = fmt.Fprintln(stderr, yellow("Run:")+"   "+cyan("sudo byn uninstall"))
		return exitErr
	}

	exe, err := os.Executable()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s resolve binary path: %v\n", boldRed("Error:"), err)
		return exitErr
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	binDir := filepath.Dir(exe)
	helperBeside := filepath.Join(binDir, "byn-exec-helper")
	manPage := filepath.Join(filepath.Dir(binDir), "share", "man", "man1", "byn.1")

	provisioned := cliProvisioned()
	vaultDir := uninstallVaultDir(provisioned, getenv)

	// Ask about the vault unless --purge already decided.
	doPurge := *purge
	if !doPurge {
		doPurge = confirmUninstallVault(vaultDir, stdin, stdout)
	}

	// --- Tear down the service / daemon ---
	if provisioned {
		if code := uninstallSystemService(doPurge, stderr); code != exitOK {
			return code
		}
	} else {
		uninstallUserDaemon(exe, getenv, stderr)
		if doPurge && vaultDir != "" {
			if rerr := os.RemoveAll(vaultDir); rerr != nil {
				_, _ = fmt.Fprintf(stderr, "warning: could not remove vault %s: %v\n", vaultDir, rerr)
			}
		}
	}

	// --- Remove binaries and man page ---
	for _, p := range []string{exe, helperBeside, manPage} {
		if rerr := os.Remove(p); rerr != nil && !os.IsNotExist(rerr) {
			_, _ = fmt.Fprintf(stderr, "warning: could not remove %s: %v\n", p, rerr)
		}
	}

	if doPurge && vaultDir != "" {
		_, _ = fmt.Fprintf(stdout, "byn uninstalled — binaries and vault removed.\n")
	} else if vaultDir != "" {
		_, _ = fmt.Fprintf(stdout, "byn uninstalled — binaries removed, vault kept at %s.\n", vaultDir)
	} else {
		_, _ = fmt.Fprintln(stdout, "byn uninstalled.")
	}
	return exitOK
}

// uninstallSystemService tears down the system service via setup.Teardown.
// "Unit not found" errors from systemctl/launchctl are treated as warnings so
// the uninstall completes even when setup was partially run.
func uninstallSystemService(purge bool, stderr io.Writer) int {
	run := privilegedRunner()
	deps := setup.TeardownDeps{
		UninstallService: func() error {
			err := privsep.UninstallService(run)
			if err != nil && isServiceNotFound(err) {
				_, _ = fmt.Fprintln(stderr, "note: byn.service not found — skipping service removal")
				return nil
			}
			return err
		},
		RemoveSpawnHelper: func() error {
			for _, p := range []string{privsep.HelperDestPath(), privsep.HelperConfigPath()} {
				if rerr := os.Remove(p); rerr != nil && !os.IsNotExist(rerr) {
					return fmt.Errorf("remove %s: %w", p, rerr)
				}
			}
			return nil
		},
		RemoveOwnerRecord: func() error {
			p := paths.OwnerRecordIn(paths.SystemDataDir())
			if rerr := os.Remove(p); rerr != nil && !os.IsNotExist(rerr) {
				return fmt.Errorf("remove owner record: %w", rerr)
			}
			return nil
		},
		SystemDataDir: paths.SystemDataDir,
		PurgeDataDir: func(systemDir string) error {
			if rerr := os.RemoveAll(systemDir); rerr != nil {
				return fmt.Errorf("remove %s: %w", systemDir, rerr)
			}
			return nil
		},
	}
	if _, err := setup.Teardown(deps, purge); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	return exitOK
}

// isServiceNotFound reports whether the error is a "unit does not exist" response
// from systemd or launchd — safe to ignore during uninstall (already gone).
func isServiceNotFound(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "does not exist") ||
		strings.Contains(s, "No such file") ||
		strings.Contains(s, "not loaded") ||
		strings.Contains(s, "exit status 5")
}

// uninstallUserDaemon stops a non-provisioned user daemon (and removes any
// user-level systemd unit installed via `byn daemon install`). Under sudo,
// both operations run as the real invoking user via su so the right home dir
// and pidfile are found.
func uninstallUserDaemon(exe string, getenv func(string) string, stderr io.Writer) {
	su := getenv("SUDO_USER")
	// Shell script: stop the daemon then remove the user-level service unit.
	// 'true' at the end ensures su exits 0 even if byn isn't running.
	script := fmt.Sprintf("%q stop 2>/dev/null; %q daemon uninstall 2>/dev/null; true", exe, exe)
	var cmd *exec.Cmd
	if su != "" {
		cmd = exec.Command("su", "-c", script, "--", su) // #nosec G204 -- su is a fixed path; su validates the username
	} else {
		cmd = exec.Command("sh", "-c", script) // #nosec G204 -- script uses quoted exe path from os.Executable()
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		_, _ = fmt.Fprintf(stderr, "note: could not stop user daemon: %s\n", strings.TrimSpace(string(out)))
	}
}

// uninstallVaultDir resolves where the vault lives: the system data dir when
// provisioned, otherwise the real invoking user's ~/.byn.
func uninstallVaultDir(provisioned bool, getenv func(string) string) string {
	if provisioned {
		return paths.SystemDataDir()
	}
	if su := getenv("SUDO_USER"); su != "" {
		if u, err := user.Lookup(su); err == nil {
			return filepath.Join(u.HomeDir, ".byn")
		}
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".byn")
	}
	return ""
}

// confirmUninstallVault asks the user whether to also delete the vault.
// Returns true only on an explicit "yes" — the safe default is to keep the vault.
func confirmUninstallVault(vaultDir string, stdin io.Reader, stdout io.Writer) bool {
	if vaultDir == "" {
		return false
	}
	_, _ = fmt.Fprintf(stdout, "Your vault at %s contains your secrets.\n", cyan(vaultDir))
	_, _ = fmt.Fprintf(stdout, "Delete it permanently? Type %s to confirm, or press Enter to keep it: ", bold("yes"))
	sc := bufio.NewScanner(stdin)
	if !sc.Scan() {
		return false
	}
	return strings.TrimSpace(sc.Text()) == "yes"
}
