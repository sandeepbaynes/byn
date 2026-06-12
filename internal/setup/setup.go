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
	// prebuilt spawn helper + helper config). Idempotent.
	InstallSpawnHelper func() error

	// InstallService installs + loads the system service (systemd unit // macOS
	// LaunchDaemon) running the daemon as _byn (privsep.InstallService). Idempotent.
	InstallService func() error

	// Relocate moves a legacy ~/.byn into the system data dir, chowned to the _byn
	// service account (migrate.Relocate). Called ONLY when LegacyDir reports the
	// legacy dir exists.
	Relocate func(legacyDir, systemDir string, uid, gid int) error

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
	OwnerUID  int    // the recorded owner UID (the invoking human)
	SystemDir string // the system data root
	Migrated  bool   // true if a legacy ~/.byn was relocated
	LegacyDir string // the legacy dir relocated FROM (only when Migrated)
}

// Provision runs the full `byn setup`: install service users + spawn helper →
// install + load the system service → relocate any legacy ~/.byn → record the
// owner UID → verify post-conditions. It is root-required (enforced by the
// caller) and idempotent. The orchestration order is load-bearing:
//
//  1. InstallSpawnHelper FIRST — creates the _byn / _byn-exec accounts; the
//     relocate's chown target and the service's User=_byn both need _byn to
//     exist before they run.
//  2. InstallService — installs + enables the system unit/LaunchDaemon (User=_byn).
//  3. Relocate (only if a legacy ~/.byn exists) — moves the old vault into the
//     system dir, chowned to _byn, BEFORE the owner record is written so a
//     verify sees a fully-populated tree.
//  4. WriteOwnerRecord — records the invoking human's UID (never 0). The owner
//     record is the authoritative "provisioned" marker (paths.Provisioned), so
//     it is written LAST: an interrupted setup before this point is not yet
//     "provisioned" and re-running is clean.
//  5. Verify — lightweight post-conditions (no daemon round-trip).
func Provision(d Deps) (Result, error) {
	ownerUID, ok := d.SudoUID()
	if !ok || ownerUID <= 0 {
		return Result{}, errNoSudoContext
	}

	// 1. Service users + spawn helper (creates _byn / _byn-exec). Idempotent.
	if err := d.InstallSpawnHelper(); err != nil {
		return Result{}, fmt.Errorf("install spawn helper / service users: %w", err)
	}

	// Resolve the _byn account now that it exists (chown target for relocate +
	// the verify ownership check).
	daemonUID, daemonGID, err := d.DaemonUser()
	if err != nil {
		return Result{}, fmt.Errorf("resolve %s service account after provisioning: %w", "_byn", err)
	}

	// 2. System service (systemd unit // LaunchDaemon), User=_byn. Idempotent.
	if err := d.InstallService(); err != nil {
		return Result{}, fmt.Errorf("install system service: %w", err)
	}

	systemDir := d.SystemDataDir()

	// 3. Relocate a legacy ~/.byn ONLY if it exists (fresh install skips this).
	res := Result{OwnerUID: ownerUID, SystemDir: systemDir}
	legacyDir, legacyExists, lerr := d.LegacyDir()
	if lerr != nil {
		return Result{}, fmt.Errorf("locate legacy data dir: %w", lerr)
	}
	if legacyExists {
		if err := d.Relocate(legacyDir, systemDir, daemonUID, daemonGID); err != nil {
			return Result{}, fmt.Errorf("relocate legacy data dir %s: %w", legacyDir, err)
		}
		res.Migrated = true
		res.LegacyDir = legacyDir
	}

	// 4. Owner record (the provisioned marker) — written LAST, never UID 0.
	ownerRecordPath := d.OwnerRecordPath()
	if err := d.WriteOwnerRecord(ownerRecordPath, ownerUID); err != nil {
		return Result{}, fmt.Errorf("record owner UID: %w", err)
	}

	// 5. Verify post-conditions (lightweight; no daemon round-trip).
	if err := d.Verify(systemDir, ownerRecordPath, ownerUID, daemonUID, daemonGID); err != nil {
		return Result{}, fmt.Errorf("verify provisioning: %w", err)
	}

	return res, nil
}
