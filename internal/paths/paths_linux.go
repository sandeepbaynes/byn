//go:build linux && !byntest

package paths

// systemDataDir is the FHS service-state path used once an install is
// provisioned to run the daemon as _byn (owned _byn:_byn, 0700, managed by the
// systemd unit's StateDirectory).
func systemDataDir() string { return "/var/lib/byn" }

// socketPath is the provisioned runtime socket (owner-traversable parent under
// /run), distinct from the _byn-owned state dir.
func socketPath() string { return "/run/byn/daemon.sock" }
