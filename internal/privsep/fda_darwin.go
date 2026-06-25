//go:build darwin

package privsep

import "os"

// fdaSentinel is a system file that exists on all supported macOS versions and
// is only readable by processes with Full Disk Access granted in
// System Settings > Privacy & Security > Full Disk Access.
const fdaSentinel = "/Library/Application Support/com.apple.TCC/TCC.db"

// CheckFDA reports whether this process has macOS Full Disk Access.
// It probes the TCC database, which is protected by TCC and only
// accessible to FDA-granted processes.  Intended to run as the _byn
// daemon user so that the caller can surface a human-actionable warning
// when the daemon cannot reach .byn files in TCC-protected directories
// (~/Documents, ~/Desktop, ~/Downloads, iCloud Drive).
func CheckFDA() bool {
	f, err := os.Open(fdaSentinel)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
