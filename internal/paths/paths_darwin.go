//go:build darwin && !byntest

package paths

func dataDir() string    { return "/Library/Application Support/byn" }
func socketPath() string { return "/Library/Application Support/byn/daemon.sock" }
