//go:build !byntest

package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

// dataDir resolves the active data root. It returns the fixed system path when
// that path already exists (i.e. byn has been provisioned there by `byn setup`
// / `byn migrate`), otherwise the legacy per-user ~/.byn. This keeps the
// opt-in-off / unprovisioned path behaving exactly as it does today (the
// `[security] privsep` flag is off by default this release — spec D3) while a
// provisioned install transparently uses the _byn-owned system path. The
// selector is filesystem state under root-owned /var/lib (or the user's own
// ~/.byn), NOT an attacker-settable env var, so it adds no attack surface
// (unlike the removed BYN_DIR — spec §6.5).
func dataDir() (string, error) {
	sys := systemDataDir()
	fi, err := os.Stat(sys)
	return resolveDataDir(sys, err == nil && fi.IsDir(), legacyDataDir)
}

// resolveDataDir is the pure selector, factored out so both branches are unit
// testable without touching the real /var/lib.
func resolveDataDir(systemDir string, systemExists bool, legacy func() (string, error)) (string, error) {
	if systemExists {
		return systemDir, nil
	}
	return legacy()
}

// legacyDataDir is the pre-NU-6 per-user data root (~/.byn), used until an
// install is provisioned to the system path.
func legacyDataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home dir for legacy data root: %w", err)
	}
	return filepath.Join(home, ".byn"), nil
}
