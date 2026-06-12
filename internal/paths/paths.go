// Package paths is the single source of truth for the byn daemon's on-disk
// locations. The data root is resolved between a fixed per-OS *system* path
// (paths_linux.go / paths_darwin.go) used once an install is provisioned, and
// the legacy per-user ~/.byn used before provisioning / when privsep is opted
// out (the `[security] privsep` flag is off by default this release — spec D3,
// so the unprovisioned path must behave exactly as it does today). Crucially
// there is NO env override in a production build — a repointable data root is
// attack surface (spec §6.5). Tests inject isolation via the byntest build tag
// (paths_testdir.go), which is never compiled into a production binary.
package paths

// DataDir resolves the active data root: the fixed system path when byn has
// been provisioned there (it exists), otherwise the legacy per-user ~/.byn.
// The error path covers an undiscoverable home dir on the legacy branch.
func DataDir() (string, error) { return dataDir() }

// SocketPath is the owner-reachable runtime socket used by a *provisioned*
// install (peercred-gated to the recorded owner UID). It is distinct from
// DataDir so a _byn:_byn 0700 state dir can stay unreadable to the human while
// the socket parent is traversable. The unprovisioned/legacy daemon keeps its
// socket inside the data dir (daemon.SocketFilename); this is wired in by the
// socket-relocation task.
func SocketPath() string { return socketPath() }

// OwnerRecordPath is the 0444 file recording the allowlisted owner UID (§6.1),
// inside the active data root.
func OwnerRecordPath() (string, error) {
	d, err := dataDir()
	if err != nil {
		return "", err
	}
	return OwnerRecordIn(d), nil
}
