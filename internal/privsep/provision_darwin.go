//go:build darwin

package privsep

import "fmt"

// helperConfigPathDarwin is the compiled-in path for the root-owned config holding
// the target UID/GID. Matches the constant in cmd/byn-exec-helper/drop_darwin.go EXACTLY.
const helperConfigPathDarwin = "/Library/Application Support/byn/exec-helper.conf"

// helperStateDirDarwin is the root-owned state directory on macOS.
const helperStateDirDarwin = "/Library/Application Support/byn"

// helperDestPathDarwin is the installed location of the privileged spawn helper on macOS.
const helperDestPathDarwin = "/usr/local/libexec/byn-exec-helper"

// HelperConfigPath returns the compiled-in, platform-specific path to the
// root-owned helper config. MUST match the helperConfigPath constant in
// cmd/byn-exec-helper/drop_darwin.go exactly — a mismatch silently breaks privsep.
func HelperConfigPath() string {
	return helperConfigPathDarwin
}

// HelperDestPath returns the installed destination path for the privileged
// spawn helper on this platform.
func HelperDestPath() string {
	return helperDestPathDarwin
}

// ProvisionResult reports what provisioning did (idempotent re-runs).
type ProvisionResult struct{ AlreadyProvisioned bool }

// runner runs a privileged command (injected for tests).
type runner func(cmd string, args ...string) error

// provisionUsers creates the service users if absent. Idempotent.
// On macOS, sysadminctl -addUser creates system accounts.
func provisionUsers(lookup uidLookup, run runner) (ProvisionResult, error) {
	_, _, eerr := lookup(ExecUser)
	_, _, derr := lookup(DaemonUser)
	if eerr == nil && derr == nil {
		return ProvisionResult{AlreadyProvisioned: true}, nil
	}
	// Create _byn daemon user if absent.
	if derr != nil {
		if err := run("sysadminctl",
			"-addUser", DaemonUser,
			"-roleAccount",
			"-shell", "/usr/bin/false",
			"-home", "/var/empty",
		); err != nil {
			return ProvisionResult{}, fmt.Errorf("create %s: %w", DaemonUser, err)
		}
	}
	// Create _byn-exec exec user if absent.
	if eerr != nil {
		if err := run("sysadminctl",
			"-addUser", ExecUser,
			"-roleAccount",
			"-shell", "/usr/bin/false",
			"-home", "/var/empty",
		); err != nil {
			return ProvisionResult{}, fmt.Errorf("create %s: %w", ExecUser, err)
		}
	}
	return ProvisionResult{}, nil
}

// installHelper installs the PREBUILT helper setuid-root (macOS has no file
// capabilities), ensures the state dir is root:wheel, and writes the
// root-owned, root-only-writable UID/GID config the helper reads.
func installHelper(run runner, srcHelperPath, destPath, configPath string, execUID, execGID int) error {
	if err := run("install", "-o", "root", "-g", "wheel", "-m", "4755", srcHelperPath, destPath); err != nil {
		return fmt.Errorf("install helper: %w", err)
	}
	// State dir root:wheel.
	if err := run("install", "-d", "-o", "root", "-g", "wheel", "-m", "0711",
		helperStateDirDarwin); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	// Write target ids root-owned + root-only-writable (0644). Helper validates.
	if err := run("sh", "-c",
		fmt.Sprintf("printf '%%d\\n%%d\\n' %d %d > %q && chown root:wheel %q && chmod 0644 %q",
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
	result, err := provisionUsers(osLookup, run)
	if err != nil {
		return err
	}
	var execUID, execGID int
	if result.AlreadyProvisioned {
		execUID, execGID, err = osLookup(ExecUser)
		if err != nil {
			return fmt.Errorf("lookup %s after provisioning: %w", ExecUser, err)
		}
	} else {
		execUID, execGID, err = osLookup(ExecUser)
		if err != nil {
			return fmt.Errorf("lookup %s after creating: %w", ExecUser, err)
		}
	}
	return installHelper(run, srcHelperPath, destPath, configPath, execUID, execGID)
}
