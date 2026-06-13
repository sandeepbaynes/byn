//go:build !linux

package privsep

// SetUndumpable is a no-op off Linux. PR_SET_DUMPABLE is a Linux prctl; macOS
// memory hardening is handled at build/sign time via the hardened runtime
// without com.apple.security.get-task-allow (see .goreleaser.yaml), and other
// platforms are out of scope. Returning nil keeps the daemon/exec-child call
// sites portable without a platform branch.
func SetUndumpable() error { return nil }
