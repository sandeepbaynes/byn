// Package paths is the single source of truth for the byn daemon's on-disk
// locations. The data root is a fixed per-OS system path (paths_linux.go /
// paths_darwin.go) with NO runtime override in a production build — a
// repointable data root is attack surface (spec §6.5). Tests inject isolation
// via the byntest build tag (paths_testdir.go), which is never compiled into a
// production binary.
package paths

// DataDir is the fixed system data root for the byn daemon. There is NO runtime
// override in a production build — a repointable data root is attack surface
// (spec §6.5). Tests inject isolation via the byntest build tag
// (paths_testdir.go).
func DataDir() string { return dataDir() } // platform value

// SocketPath is the owner-reachable runtime socket (peercred-gated to the
// recorded owner UID). Distinct from DataDir so a _byn:_byn 0700 state dir can
// stay unreadable to the human while the socket parent is traversable.
func SocketPath() string { return socketPath() }

// OwnerRecordPath is the 0444 file recording the allowlisted owner UID (§6.1).
func OwnerRecordPath() string { return dataDir() + "/owner" }
