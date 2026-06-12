//go:build !linux && !darwin

package daemon

// procInfo is a no-op on platforms without a supported lookup. Caller
// UID/PID are still recorded; the process name is simply empty.
func procInfo(_ int) (comm string, ppid int) { return "", 0 }

// NOTE: ttyDev binding is a no-op on this platform (returns 0 = uid-only
// binding). Same-UID TIOCSCTTY tty acquisition is therefore not a concern
// here; the Unix socket's mode-0600 uid gate is the sole binding.
//
// peerTTYDev is a no-op on unsupported platforms; callers use uid-only binding.
func peerTTYDev(_ int) int32 { return 0 }
