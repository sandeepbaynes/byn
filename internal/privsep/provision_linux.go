//go:build linux

package privsep

import (
	"fmt"
	"path/filepath"
)

// helperConfigPathLinux is the compiled-in path for the root-owned config
// holding the target UID/GID. It lives BESIDE the helper binary in the root-owned
// /usr/local/libexec — NOT inside the _byn-owned /var/lib/byn state dir — so the
// helper's "all parent dirs root-owned" invariant holds (systemd's StateDirectory
// makes /var/lib/byn _byn-owned), the daemon user cannot rewrite the config the
// setuid helper trusts, and it does not collide with `byn migrate` adopting the
// vault into the state dir. Matches the constant in
// cmd/byn-exec-helper/drop_linux.go EXACTLY.
const helperConfigPathLinux = "/usr/local/libexec/byn-exec-helper.conf"

// helperDestPathLinux is the installed location of the privileged spawn helper on Linux.
const helperDestPathLinux = "/usr/local/libexec/byn-exec-helper"

// HelperConfigPath returns the compiled-in, platform-specific path to the
// root-owned helper config. MUST match the helperConfigPath constant in
// cmd/byn-exec-helper/drop_linux.go exactly — a mismatch silently breaks privsep.
func HelperConfigPath() string {
	return helperConfigPathLinux
}

// HelperDestPath returns the installed destination path for the privileged
// spawn helper on this platform.
func HelperDestPath() string {
	return helperDestPathLinux
}

// sysusersDropDir is the standard drop-in directory for systemd-sysusers.
// Some older distros use /etc/sysusers.d instead.
const sysusersDropDir = "/usr/lib/sysusers.d"

// sysusersConf returns the declarative sysusers.d content creating both service
// users as system accounts with no login shell. Applied via systemd-sysusers.
func sysusersConf() string {
	return "#Type Name      ID GECOS              Home Shell\n" +
		"u     _byn      -  \"byn vault daemon\" -    /usr/sbin/nologin\n" +
		"u     _byn-exec -  \"byn exec sandbox\" -    /usr/sbin/nologin\n"
}

// ProvisionResult reports what provisioning did (idempotent re-runs).
type ProvisionResult struct{ AlreadyProvisioned bool }

// runner runs a privileged command (injected for tests).
type runner func(cmd string, args ...string) error

// provisionUsers creates the service users if absent. Idempotent.
func provisionUsers(lookup uidLookup, run runner) (ProvisionResult, error) {
	_, _, eerr := lookup(ExecUser)
	_, _, derr := lookup(DaemonUser)
	if eerr == nil && derr == nil {
		return ProvisionResult{AlreadyProvisioned: true}, nil
	}
	conf := sysusersConf()
	if err := run("sh", "-c",
		fmt.Sprintf("printf '%%s' %q > "+sysusersDropDir+"/byn.conf && systemd-sysusers", conf)); err != nil {
		return ProvisionResult{}, fmt.Errorf("create service users: %w", err)
	}
	return ProvisionResult{}, nil
}

// installHelper installs the PREBUILT helper root-owned with file caps, ensures
// the state dir + all parents are root-owned (the install invariant the helper's
// O_NOFOLLOW config check relies on), and writes the root-owned, root-only-
// writable UID/GID config the helper reads. The helper is shipped in the release
// — NOT built here. configPath is the helper's compiled-in path.
func installHelper(run runner, srcHelperPath, destPath, configPath string, execUID, execGID int) error {
	// Ensure the helper's parent dir exists first: /usr/local/libexec is not
	// present by default on many distros, and `install <src> <dest>` does not
	// create it (it stages a temp file IN the dest dir → ENOENT if absent).
	if err := run("install", "-d", "-o", "root", "-g", "root", "-m", "0755", filepath.Dir(destPath)); err != nil {
		return fmt.Errorf("create helper dir: %w", err)
	}
	if err := run("install", "-o", "root", "-g", "root", "-m", "0755", srcHelperPath, destPath); err != nil {
		return fmt.Errorf("install helper: %w", err)
	}
	if err := run("setcap", "cap_setuid,cap_setgid+ep", destPath); err != nil {
		return fmt.Errorf("setcap helper: %w", err)
	}
	// Pre-create the state dir so the owner record + relocate target exist before
	// the service starts; systemd's StateDirectory re-owns /var/lib/byn to
	// _byn:_byn 0700 when the unit starts.
	if err := run("install", "-d", "-o", "root", "-g", "root", "-m", "0711", "/var/lib/byn"); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	// Write target ids root-owned + root-only-writable (0644). Helper validates.
	if err := run("sh", "-c",
		fmt.Sprintf("printf '%%d\\n%%d\\n' %d %d > %q && chown root:root %q && chmod 0644 %q",
			execUID, execGID, configPath, configPath, configPath)); err != nil {
		return fmt.Errorf("write helper config: %w", err)
	}
	return nil
}

// Setup provisions the service users and installs the privileged spawn helper.
// It is idempotent: re-running when already provisioned still (re)installs the
// helper and config, then exits 0. srcHelperPath is the prebuilt binary
// (shipped beside the byn binary); destPath is where it is installed;
// configPath is the root-owned config the helper reads at runtime.
func Setup(run runner, srcHelperPath, destPath, configPath string) error {
	if _, err := provisionUsers(osLookup, run); err != nil {
		return err
	}
	execUID, execGID, err := osLookup(ExecUser)
	if err != nil {
		return fmt.Errorf("lookup %s after provisioning: %w", ExecUser, err)
	}
	return installHelper(run, srcHelperPath, destPath, configPath, execUID, execGID)
}
