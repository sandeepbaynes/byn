//go:build linux && !byntest

package paths

func dataDir() string    { return "/var/lib/byn" }
func socketPath() string { return "/run/byn/daemon.sock" }
