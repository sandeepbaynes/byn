package setup

import "fmt"

// TeardownDeps are the injectable seams `byn setup --uninstall` depends on. As
// with [Deps], every side effect is injected so the reversal sequence is
// unit-testable without root, systemd, or launchd.
type TeardownDeps struct {
	// UninstallService disables + stops the system service and removes the unit/
	// plist (privsep.UninstallService). It deliberately leaves the service
	// accounts and the vault state in place — those are separate concerns.
	UninstallService func() error

	// RemoveSpawnHelper removes the installed spawn helper binary and its config
	// (privsep.HelperDestPath / HelperConfigPath). Absent files are not an error.
	RemoveSpawnHelper func() error

	// RemoveOwnerRecord removes the owner-record file (the "provisioned" marker).
	// After this the install reads as unprovisioned again. Absent is not an error.
	RemoveOwnerRecord func() error

	// SystemDataDir returns the system data root (the vault tree). Only used when
	// Purge is requested.
	SystemDataDir func() string

	// PurgeDataDir removes the ENTIRE system data dir (the vault). It is gated
	// behind the Purge flag + a confirmation in the caller — Teardown NEVER calls
	// it unless Purge is true.
	PurgeDataDir func(systemDir string) error
}

// TeardownResult reports what Teardown did, for the caller's message.
type TeardownResult struct {
	Purged    bool   // true if the system data dir (vault) was removed
	SystemDir string // the system data root (only meaningful when Purged)
}

// Teardown reverses Provision: uninstall the system service, remove the spawn
// helper, and remove the owner record. It LEAVES the vault/state intact by
// default — destroying the vault requires the explicit purge flag.
//
// Order: stop the service FIRST (so nothing is reading the state while we tear
// down), then remove the helper + owner record, then — only when purge is true —
// remove the vault. Removing the owner record before purging is harmless; the
// purge wipes the whole dir anyway.
//
// purge MUST already have been confirmed by the caller (a loud confirmation
// gate). Teardown does not prompt; it only honors the boolean. When purge is
// false the vault is never touched, no matter what.
func Teardown(d TeardownDeps, purge bool) (TeardownResult, error) {
	if err := d.UninstallService(); err != nil {
		return TeardownResult{}, fmt.Errorf("uninstall system service: %w", err)
	}
	if err := d.RemoveSpawnHelper(); err != nil {
		return TeardownResult{}, fmt.Errorf("remove spawn helper: %w", err)
	}
	if err := d.RemoveOwnerRecord(); err != nil {
		return TeardownResult{}, fmt.Errorf("remove owner record: %w", err)
	}

	res := TeardownResult{}
	if purge {
		systemDir := d.SystemDataDir()
		if err := d.PurgeDataDir(systemDir); err != nil {
			return TeardownResult{}, fmt.Errorf("purge system data dir %s: %w", systemDir, err)
		}
		res.Purged = true
		res.SystemDir = systemDir
	}
	return res, nil
}
