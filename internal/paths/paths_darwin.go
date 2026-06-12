//go:build darwin && !byntest

package paths

// systemDataDir is the macOS system-service state path used once an install is
// provisioned to run the daemon as _byn (owned _byn, 0700).
func systemDataDir() string { return "/Library/Application Support/byn" }

// socketPath is the provisioned runtime socket under the support dir.
func socketPath() string { return "/Library/Application Support/byn/daemon.sock" }
