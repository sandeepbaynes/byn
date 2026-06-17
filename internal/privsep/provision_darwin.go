//go:build darwin

package privsep

import (
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"
)

// helperConfigPathDarwin is the compiled-in path for the root-owned config
// holding the target UID/GID. It lives BESIDE the helper binary in the
// root-owned /usr/local/libexec — NOT inside the _byn-owned vault data dir — so
// (a) the daemon user can never rewrite the config the setuid-root helper trusts
// (the helper requires root-owned parents; see byn-exec-helper readTargetIDs) and
// (b) it does not collide with `byn migrate` adopting the vault into the data dir.
// Matches the constant in cmd/byn-exec-helper/drop_darwin.go EXACTLY.
const helperConfigPathDarwin = "/usr/local/libexec/byn-exec-helper.conf"

// systemDataDirDarwin is the fixed system data root (the vault tree) on macOS,
// owned _byn:_byn. `byn setup` pre-creates it (empty) so the owner record has a
// home on a fresh install; `byn migrate` adopts a legacy vault into it.
const systemDataDirDarwin = "/Library/Application Support/byn"

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

// darwinServiceIDMin/Max bound the UID/GID band byn allocates its service
// accounts from. It is below 500 (hidden from the login window by the
// Hide500Users convention) and above Apple's own _daemon cluster (which packs
// the 200-400 range on current macOS), so byn's accounts do not collide with
// system daemons.
const (
	darwinServiceIDMin = 450
	darwinServiceIDMax = 499
)

// provisionUsers creates the _byn and _byn-exec service accounts if absent.
// Idempotent: when both already exist it is a no-op.
//
// Each account is created with dscl at a free UID/GID byn picks from its hidden
// service band (uid == gid, the _www/_mysql convention), login disabled
// (Password "*", /usr/bin/false shell, /var/empty home) and hidden from the
// login UI. byn does NOT use `sysadminctl -roleAccount`: its required UID range
// is macOS-version-dependent (200-400 historically, 450-499 on macOS 26) so no
// fixed UID is portable, and it exits 0 even when it refuses to create the
// account — masking the failure until a later lookup. dscl imposes no range,
// lets byn choose the UID itself, and returns real exit codes so a creation
// failure surfaces here as an actionable error.
func provisionUsers(lookup uidLookup, run runner, idInUse func(int) bool) (ProvisionResult, error) {
	_, _, eerr := lookup(ExecUser)
	_, _, derr := lookup(DaemonUser)
	if eerr == nil && derr == nil {
		return ProvisionResult{AlreadyProvisioned: true}, nil
	}

	accounts := []struct {
		name, realName string
		missing        bool
	}{
		{DaemonUser, "byn daemon service account", derr != nil},
		{ExecUser, "byn exec service account", eerr != nil},
	}

	allocated := map[int]bool{}
	for _, a := range accounts {
		if !a.missing {
			continue
		}
		id, err := chooseFreeID(darwinServiceIDMin, darwinServiceIDMax, idInUse, allocated)
		if err != nil {
			return ProvisionResult{}, fmt.Errorf("allocate id for %s: %w", a.name, err)
		}
		allocated[id] = true
		if err := createServiceUser(run, a.name, a.realName, id); err != nil {
			return ProvisionResult{}, fmt.Errorf("create %s: %w", a.name, err)
		}
	}
	return ProvisionResult{}, nil
}

// chooseFreeID returns the first id in [minID,maxID] that is neither already
// allocated earlier in this run nor present as a UID/GID in the OS directory.
func chooseFreeID(minID, maxID int, inUse func(int) bool, allocated map[int]bool) (int, error) {
	for id := minID; id <= maxID; id++ {
		if allocated[id] || inUse(id) {
			continue
		}
		return id, nil
	}
	return 0, fmt.Errorf("no free service account id available in %d-%d", minID, maxID)
}

// createServiceUser creates a hidden, login-disabled service account and its
// matching primary group at id, via dscl. Order matters: the group is created
// before the user that references it as PrimaryGroupID. Each step is checked, so
// a dscl failure (non-zero exit) stops provisioning with a wrapped error rather
// than leaving a half-built account to surface as a confusing lookup miss later.
func createServiceUser(run runner, name, realName string, id int) error {
	sid := strconv.Itoa(id)
	group := "/Groups/" + name
	usr := "/Users/" + name
	steps := [][]string{
		{".", "-create", group},
		{".", "-create", group, "PrimaryGroupID", sid},
		{".", "-create", group, "RealName", realName},
		{".", "-create", group, "Password", "*"},
		{".", "-create", usr},
		{".", "-create", usr, "RealName", realName},
		{".", "-create", usr, "UniqueID", sid},
		{".", "-create", usr, "PrimaryGroupID", sid},
		{".", "-create", usr, "UserShell", "/usr/bin/false"},
		{".", "-create", usr, "NFSHomeDirectory", "/var/empty"},
		{".", "-create", usr, "Password", "*"},
		{".", "-create", usr, "IsHidden", "1"},
	}
	for _, s := range steps {
		if err := run("dscl", s...); err != nil {
			return fmt.Errorf("dscl %v: %w", s, err)
		}
	}
	return nil
}

// osIDInUse reports whether id is already taken as a UID or GID in the OS
// directory; backs the production free-id scan in provisionUsers.
func osIDInUse(id int) bool {
	s := strconv.Itoa(id)
	if _, err := user.LookupId(s); err == nil {
		return true
	}
	if _, err := user.LookupGroupId(s); err == nil {
		return true
	}
	return false
}

// installHelper installs the PREBUILT helper setuid-root (macOS has no file
// capabilities), ensures the state dir is root:wheel, and writes the
// root-owned, root-only-writable UID/GID config the helper reads.
func installHelper(run runner, srcHelperPath, destPath, configPath string, execUID, execGID int) error {
	// Ensure the helper's parent dir exists first: /usr/local/libexec is not
	// present by default on macOS, and `install <src> <dest>` does not create it
	// — it stages a temp file IN the dest dir, so a missing dir fails with ENOENT.
	if err := run("install", "-d", "-o", "root", "-g", "wheel", "-m", "0755",
		filepath.Dir(destPath)); err != nil {
		return fmt.Errorf("create helper dir: %w", err)
	}
	if err := run("install", "-o", "root", "-g", "wheel", "-m", "4755", srcHelperPath, destPath); err != nil {
		return fmt.Errorf("install helper: %w", err)
	}
	// Write target ids root-owned + root-only-writable (0644). Helper validates.
	if err := run("sh", "-c",
		fmt.Sprintf("printf '%%d\\n%%d\\n' %d %d > %q && chown root:wheel %q && chmod 0644 %q",
			execUID, execGID, configPath, configPath, configPath)); err != nil {
		return fmt.Errorf("write helper config: %w", err)
	}
	return nil
}

// ensureDataDir creates the system data root owned by the daemon user (_byn) so
// the separate-UID daemon can write its vault on a fresh install. On a legacy
// upgrade the relocate later replaces this empty dir with the adopted _byn-owned
// vault tree (an empty dir is a valid adopt target — see migrate commitAdopt).
// Idempotent: install -d re-applies owner/mode to an existing dir.
//
// Mode 0711, NOT 0700: macOS co-locates the daemon socket (daemon.sock) inside
// this dir, and the human owner — a DIFFERENT UID than _byn — must be able to
// TRAVERSE the dir to reach the peercred-gated socket. 0711 grants traverse
// (o+x) but NOT read/list (no o+r), so the owner cannot enumerate or read the
// vault; the vault files stay 0600 _byn. (Linux needs no equivalent — its socket
// lives in a separate /run/byn 0755 dir, so /var/lib/byn stays 0700.)
func ensureDataDir(run runner, daemonUID, daemonGID int) error {
	if err := run("install", "-d",
		"-o", strconv.Itoa(daemonUID), "-g", strconv.Itoa(daemonGID),
		"-m", "0711", systemDataDirDarwin); err != nil {
		return fmt.Errorf("create system data dir: %w", err)
	}
	return nil
}

// Setup provisions the service users, installs the privileged spawn helper, and
// creates the _byn-owned system data dir. It is idempotent: re-running when
// already provisioned still (re)installs the helper and config and re-asserts the
// data dir, then exits 0. srcHelperPath is the prebuilt binary (shipped beside
// the byn binary); destPath is where it is installed; configPath is the
// root-owned config the helper reads at runtime.
func Setup(run runner, srcHelperPath, destPath, configPath string) error {
	if _, err := provisionUsers(osLookup, run, osIDInUse); err != nil {
		return err
	}
	execUID, execGID, err := osLookup(ExecUser)
	if err != nil {
		return fmt.Errorf("lookup %s after provisioning: %w", ExecUser, err)
	}
	if err := installHelper(run, srcHelperPath, destPath, configPath, execUID, execGID); err != nil {
		return err
	}
	// The data dir must be owned by the daemon user (_byn), not the exec user, so
	// the daemon can write its vault — resolve _byn now that it exists.
	daemonUID, daemonGID, err := osLookup(DaemonUser)
	if err != nil {
		return fmt.Errorf("lookup %s after provisioning: %w", DaemonUser, err)
	}
	return ensureDataDir(run, daemonUID, daemonGID)
}
