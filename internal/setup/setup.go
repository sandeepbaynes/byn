// Package setup orchestrates the full `byn setup` provisioning flow and its
// reverse (`byn setup --uninstall`). It is the single composition point that
// wires together the three lower layers — internal/privsep (service users +
// spawn helper + system service install/uninstall + owner record), internal/
// migrate (legacy ~/.byn relocate), and internal/paths (the fixed system data
// root + owner-record location) — into one idempotent, root-required operation.
//
// Layering: privsep does NOT import migrate (that would be a security-core
// package reaching up into a migration helper); this package sits ABOVE both
// and composes them, keeping the dependency graph acyclic. Every side effect
// arrives via an injected function on [Deps], so the orchestration is fully
// unit-testable WITHOUT root, systemd, launchd, or a real /var/lib (mirroring
// how internal/privsep's service install and internal/migrate test by injecting
// a runner / chowner / relocate seam).
package setup

import (
	"errors"
	"fmt"
	"path/filepath"
)

// Deps are the injectable seams the orchestration depends on. Production wiring
// lives in the caller (cmd/byn/cmd_setup.go via DefaultProvisionDeps); tests
// inject fakes that record the call sequence.
//
// The two service-account/helper steps (InstallSpawnHelper, InstallService) are
// already idempotent in internal/privsep; the migrate step is gated on the
// legacy dir actually existing; WriteOwnerRecord overwrites atomically. So
// re-running Provision on an already-provisioned host is a clean no-op modulo
// re-installing the (identical) helper + service, which is by design (an upgrade
// re-runs setup to pick up a new helper/binary).
type Deps struct {
	// SudoUID resolves the INVOKING HUMAN's UID — the owner to allowlist on the
	// peercred-gated socket. `byn setup` runs under sudo, so the process euid is
	// 0; the owner is whoever ran sudo (the SUDO_UID env value). It returns
	// (0,false) when there is no sudo context (someone ran as real root), which
	// Provision turns into a hard error rather than recording owner UID 0.
	SudoUID func() (uid int, ok bool)

	// LegacyDir resolves the invoking human's legacy ~/.byn (SUDO_USER's home +
	// /.byn), and whether it exists. Migration only runs when it exists; a fresh
	// install skips it. An error is a hard failure (we could not even determine
	// whether there is a legacy vault to preserve).
	LegacyDir func() (dir string, exists bool, err error)

	// SystemDataDir returns the fixed per-OS system data root (paths.SystemDataDir).
	SystemDataDir func() string

	// OwnerRecordPath returns the owner-record path inside the system data dir
	// (paths.OwnerRecordIn(SystemDataDir())).
	OwnerRecordPath func() string

	// DaemonUser resolves the _byn service account uid/gid (privsep.LookupDaemonUser)
	// used as the chown target for a relocate. It errors if the account is absent
	// — but Provision creates the accounts first, so by the time it is called the
	// account exists.
	DaemonUser func() (uid, gid int, err error)

	// InstallSpawnHelper runs privsep.Setup (create service users + install the
	// prebuilt spawn helper + helper config + the _byn-owned system data dir).
	// Idempotent.
	InstallSpawnHelper func() error

	// InstallService installs + loads the system service (systemd unit // macOS
	// LaunchDaemon) running the daemon as _byn (privsep.InstallService). Idempotent.
	InstallService func() error

	// Relocate moves a legacy ~/.byn into the system data dir, chowned to the _byn
	// service account (migrate.Relocate). Called ONLY when LegacyDir reports the
	// legacy dir exists.
	Relocate func(legacyDir, systemDir string, uid, gid int) error

	// GrantHomeAccess grants the _byn daemon read+execute access to the owner's
	// home directory so the web portal's import file picker can enumerate from
	// home. On macOS, FDA grants this implicitly; on Linux it sets an ACL via
	// setfacl. Best-effort: Provision records a warning in Result.HomeACLWarning
	// on failure but does not abort — a missing setfacl binary must not break setup.
	GrantHomeAccess func(homeDir string) error

	// WriteOwnerRecord records the allowlisted owner UID at path
	// (privsep.WriteOwnerRecord). uid is the SUDO_UID resolved above (never 0).
	WriteOwnerRecord func(path string, uid int) error

	// Verify performs the lightweight post-conditions check (system data dir
	// exists + owned by _byn, owner record readable). It does NOT require a full
	// daemon round-trip — starting the daemon as _byn mid-setup is fragile in the
	// install context (the service may still be coming up). It returns an error
	// describing the first failed post-condition.
	Verify func(systemDir, ownerRecordPath string, ownerUID, daemonUID, daemonGID int) error
}

// errNoSudoContext is returned (wrapped) when Provision cannot determine the
// invoking human's UID — `byn setup` was run as real root, not via sudo. We
// refuse to record owner UID 0 (that would allowlist root, defeating privsep).
var errNoSudoContext = errors.New(
	"byn setup could not determine your owner UID (no SUDO_UID): run `byn setup` via sudo " +
		"as your normal user (e.g. `sudo byn setup`), not as root directly, so byn can record your owner UID")

// Result reports what Provision did, for the caller's success message.
type Result struct {
	OwnerUID       int    // the recorded owner UID (the invoking human)
	SystemDir      string // the system data root
	Migrated       bool   // true if a legacy ~/.byn was relocated
	LegacyDir      string // the legacy dir relocated FROM (only when Migrated)
	HomeACLWarning string // non-empty if GrantHomeAccess failed (best-effort; non-fatal)
}

// Provision runs the full `byn setup`: provision service users + spawn helper +
// the _byn-owned data dir → relocate any legacy ~/.byn → record the owner UID →
// install + start the system service → verify. It is root-required (enforced by
// the caller) and idempotent. The order is load-bearing — the service that runs
// the daemon as _byn starts LAST, only once everything it reads is in place:
//
//  1. InstallSpawnHelper FIRST — creates the _byn / _byn-exec accounts and the
//     _byn-owned system data dir; the relocate's chown target and the service's
//     User=_byn both need _byn to exist before they run.
//  2. Relocate (only if a legacy ~/.byn exists) — moves the old vault into the
//     system dir, chowned to _byn, BEFORE the service starts so the daemon never
//     races the adopt or boots against an empty, not-yet-owned data dir.
//  3. WriteOwnerRecord — records the invoking human's UID (never 0), before the
//     daemon starts so it allowlists the owner on first boot.
//  4. InstallService LAST — installs + starts the system unit/LaunchDaemon
//     (User=_byn), now that the data dir is _byn-owned + populated and the owner
//     record exists. The owner record is the authoritative "provisioned" marker;
//     an interrupted setup before the service step is not yet "provisioned" and
//     re-running is clean.
//  5. Verify — lightweight post-conditions (no daemon round-trip).
func Provision(d Deps) (Result, error) {
	ownerUID, ok := d.SudoUID()
	if !ok || ownerUID <= 0 {
		return Result{}, errNoSudoContext
	}

	// 1. Service users + spawn helper + the _byn-owned data dir. Idempotent.
	if err := d.InstallSpawnHelper(); err != nil {
		return Result{}, fmt.Errorf("install spawn helper / service users: %w", err)
	}

	// Resolve the _byn account now that it exists (chown target for relocate +
	// the verify ownership check).
	daemonUID, daemonGID, err := d.DaemonUser()
	if err != nil {
		return Result{}, fmt.Errorf("resolve %s service account after provisioning: %w", "_byn", err)
	}

	systemDir := d.SystemDataDir()

	// 2. Relocate a legacy ~/.byn ONLY if it exists (fresh install skips this).
	//    Done BEFORE the service starts so the daemon never races the adopt.
	res := Result{OwnerUID: ownerUID, SystemDir: systemDir}
	legacyDir, legacyExists, lerr := d.LegacyDir()
	if lerr != nil {
		return Result{}, fmt.Errorf("locate legacy data dir: %w", lerr)
	}

	// Grant _byn read+execute on the owner's home directory so the web portal's
	// import file picker can list the filesystem from home (analogous to macOS FDA).
	// Best-effort: a missing setfacl or restricted filesystem must not abort setup.
	if legacyDir != "" {
		if homeDir := filepath.Dir(legacyDir); homeDir != "" && homeDir != "." {
			if herr := d.GrantHomeAccess(homeDir); herr != nil {
				res.HomeACLWarning = fmt.Sprintf(
					"could not grant %s read access to home directory %s: %v; "+
						"the web portal file picker may show 'permission denied' — "+
						"run `sudo setfacl -m u:_byn:rx %s` manually to fix",
					"_byn", homeDir, herr, homeDir)
			}
		}
	}

	if legacyExists {
		if err := d.Relocate(legacyDir, systemDir, daemonUID, daemonGID); err != nil {
			return Result{}, fmt.Errorf("relocate legacy data dir %s: %w", legacyDir, err)
		}
		res.Migrated = true
		res.LegacyDir = legacyDir
	}

	// 3. Owner record (the provisioned marker), never UID 0. Written before the
	//    service starts so the daemon allowlists the owner on first boot.
	ownerRecordPath := d.OwnerRecordPath()
	if err := d.WriteOwnerRecord(ownerRecordPath, ownerUID); err != nil {
		return Result{}, fmt.Errorf("record owner UID: %w", err)
	}

	// 4. System service (systemd unit // LaunchDaemon), User=_byn — installed +
	//    started LAST, once the data dir is _byn-owned, the vault is in place, and
	//    the owner record exists. Starting it earlier races the relocate and boots
	//    the daemon against a not-yet-owned, empty data dir. Idempotent.
	if err := d.InstallService(); err != nil {
		return Result{}, fmt.Errorf("install system service: %w", err)
	}

	// 5. Verify post-conditions (lightweight; no daemon round-trip).
	if err := d.Verify(systemDir, ownerRecordPath, ownerUID, daemonUID, daemonGID); err != nil {
		return Result{}, fmt.Errorf("verify provisioning: %w", err)
	}

	return res, nil
}
