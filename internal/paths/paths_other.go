//go:build !linux && !darwin && !byntest

package paths

// Stub for platforms byn does not target for production deployment (Windows,
// the BSDs, etc.). It keeps the package building cross-platform; byn's daemon
// is supported only on Linux and macOS. The path mirrors the Linux layout so a
// curious cross-build has a sensible, non-empty value rather than "".
func systemDataDir() string { return "/var/lib/byn" }
func socketPath() string    { return "/var/lib/byn/daemon.sock" }
