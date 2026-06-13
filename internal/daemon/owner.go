package daemon

import (
	"errors"
	"fmt"
	"os"

	"github.com/sandeepbaynes/byn/internal/paths"
	"github.com/sandeepbaynes/byn/internal/privsep"
)

// resolveOwnerRecord reads the owner-UID record from the daemon's data dir and
// reports whether the install is provisioned. A missing record ⇒
// (false, 0, nil): unprovisioned, the daemon keeps geteuid(). A PRESENT but
// corrupt/garbage record ⇒ an error, NOT a silent fall back to euid: under
// privsep euid is _byn (not the owner), so silently allowlisting it would either
// lock the owner out or — worse — open the socket to the wrong UID. Fail safe
// and refuse to start (NU-6 note #2).
func resolveOwnerRecord(dataDir string) (exists bool, uid int, err error) {
	recPath := paths.OwnerRecordIn(dataDir)
	if _, statErr := os.Stat(recPath); statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return false, 0, nil
		}
		return false, 0, fmt.Errorf("daemon: stat owner record: %w", statErr)
	}
	recorded, rerr := privsep.ReadOwnerRecord(recPath)
	if rerr != nil {
		return false, 0, fmt.Errorf("daemon: owner record present but unreadable (run `byn setup`): %w", rerr)
	}
	return true, recorded, nil
}

// resolveOwnerUID decides which UID the peercred gate allowlists.
//
// When the install is provisioned (an owner record exists), the recorded owner
// UID wins — the daemon runs as the _byn service user, whose euid is NOT the
// human owner, so inferring the owner from geteuid() would lock the human out
// (NU-6 critical note #1: "the owner is no longer the daemon"). When NOT
// provisioned (opt-in privsep off), the daemon runs owner-UID exactly as today,
// so euid is the owner — no behavior change for current installs (spec D3).
//
// It is a pure function (no syscalls) so both branches are unit-tested without
// root: the caller reads the record + euid and passes the values in.
func resolveOwnerUID(recordExists bool, recorded int, euid int) uint32 {
	if recordExists {
		return uint32(recorded) //nolint:gosec // recorded is validated > 0 by privsep.ReadOwnerRecord
	}
	return uint32(euid) //nolint:gosec // euid is validated >= 0 by the caller
}
