//go:build !darwin

package privsep

// InstalledServiceExecPath is macOS-only: Full Disk Access is a macOS
// concept, and the LaunchDaemon plist it reads exists only there.
func InstalledServiceExecPath() (string, error) { return "", ErrUnsupported }
