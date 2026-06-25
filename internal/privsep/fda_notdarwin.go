//go:build !darwin

package privsep

// CheckFDA is a no-op on non-Darwin platforms. Full Disk Access (TCC)
// is a macOS-only privacy mechanism; this stub always returns false.
// Callers must guard on runtime.GOOS == "darwin" before interpreting
// the result as meaningful.
func CheckFDA() bool { return false }
