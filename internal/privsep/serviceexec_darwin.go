//go:build darwin

package privsep

import "os"

// InstalledServiceExecPath returns the byn binary the installed LaunchDaemon
// runs — the file that needs Full Disk Access. The plist is root-owned 0644,
// so the owner can read it without privilege.
func InstalledServiceExecPath() (string, error) {
	data, err := os.ReadFile(launchDaemonPlistPath)
	if err != nil {
		return "", err
	}
	return ServiceExecPathFromPlist(data)
}
