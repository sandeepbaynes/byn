//go:build !linux && !darwin

package daemon

// procInfo is a no-op on platforms without a supported lookup. Caller
// UID/PID are still recorded; the process name is simply empty.
func procInfo(_ int) (comm string, ppid int) { return "", 0 }
