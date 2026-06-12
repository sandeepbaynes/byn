package paths

import (
	"errors"
	"os"
	"path/filepath"
)

// socketFilename is the Unix-socket filename inside a data dir, for the
// unprovisioned/legacy daemon. It mirrors daemon.SocketFilename but is defined
// here to keep internal/paths free of an import cycle (internal/daemon imports
// internal/paths, not the reverse).
const socketFilename = "daemon.sock"

// ownerRecordFilename is the basename of the owner-UID record inside a data
// dir. OwnerRecordPath joins it onto the *resolved* data root; OwnerRecordIn
// joins it onto a caller-supplied root so the daemon/CLI test their ACTUAL
// data dir rather than a re-resolved one.
const ownerRecordFilename = "owner"

// OwnerRecordIn returns the owner-record path for an explicit data dir. The
// daemon passes its real cfg.Dir (which may be a test tempdir) so the
// "provisioned" signal reflects that exact directory, not a re-resolution.
func OwnerRecordIn(dataDir string) string {
	return filepath.Join(dataDir, ownerRecordFilename)
}

// ProvisionedIn reports whether the given data dir holds an owner record (the
// authoritative "set up by `byn setup`" marker). Used by both the daemon and
// the CLI against their actual data dir so they always agree.
func ProvisionedIn(dataDir string) (bool, error) {
	return ownerRecordExists(OwnerRecordIn(dataDir))
}

// Provisioned reports whether this install has been set up by `byn setup`. The
// authoritative marker is the owner-record file existing inside the active data
// root: that file is written ONLY by `byn setup` (privsep.WriteOwnerRecord), so
// its presence means the daemon should allowlist the recorded owner UID and use
// the runtime socket rather than running owner-UID at the data-dir socket. A
// dataDir-resolution error propagates; a stat error other than "not exist" also
// propagates so a permissions glitch is never silently read as "unprovisioned".
func Provisioned() (bool, error) {
	d, err := dataDir()
	if err != nil {
		return false, err
	}
	return ProvisionedIn(d)
}

// ownerRecordExists is the stat half of Provisioned, split out so the
// active-path resolvers can reuse it.
func ownerRecordExists(ownerRecordPath string) (bool, error) {
	_, err := os.Stat(ownerRecordPath)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// ActiveSocketPath returns the socket BOTH the daemon binds and the CLI
// connects to, given the active data dir. It is the single source of truth for
// socket location so the bind side and the connect side can never disagree:
//
//   - provisioned (owner record present) ⇒ the runtime socket (SocketPath),
//     whose parent is owner-traversable while the _byn-owned state dir stays
//     0700-private to the human;
//   - unprovisioned / legacy ⇒ the socket inside the data dir, exactly as the
//     owner-UID daemon uses today (no behavior change — spec D3).
func ActiveSocketPath(dataDir string) (string, error) {
	prov, err := ProvisionedIn(dataDir)
	if err != nil {
		return "", err
	}
	return resolveActiveSocketPath(dataDir, prov, SocketPath()), nil
}

// resolveActiveSocketPath is the pure selector behind ActiveSocketPath, factored
// out so both branches are unit-testable without touching the filesystem.
func resolveActiveSocketPath(dataDir string, provisioned bool, runtimeSocket string) string {
	if provisioned {
		return runtimeSocket
	}
	return filepath.Join(dataDir, socketFilename)
}
