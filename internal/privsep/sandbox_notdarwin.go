//go:build !darwin

package privsep

// ExecSandboxProfile returns "" off macOS: Seatbelt / sandbox-exec is a macOS
// facility, so a terminal-anchored exec child runs unsandboxed on other
// platforms (the _byn-exec UID boundary remains the load-bearing control; Linux
// confinement is future work). The helper, seeing an empty profile, execs the
// target directly.
func ExecSandboxProfile(stateDir, socketPath string, noNetwork bool) string { return "" }
