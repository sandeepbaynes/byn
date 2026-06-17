//go:build darwin

package privsep

import (
	"fmt"
	"strings"
)

// SandboxOpts configures the Seatbelt (sandbox-exec) profile for an exec child.
type SandboxOpts struct {
	StateDir   string // byn's data dir — child is denied all access to it
	SocketPath string // the daemon socket — child is denied access
	NoNetwork  bool   // per-action tightening: deny all network
}

// seatbeltProfile builds a TARGETED SBPL profile: allow-by-default (so arbitrary
// approved commands run), with specific denials of byn's own socket + state dir
// (defense in depth on top of the _byn-exec UID boundary), and an optional
// network denial. NOT default-deny — that would break real actions (pnpm, etc.).
//
// sandbox-exec/SBPL is deprecated-but-ubiquitous (Chromium/Bazel); the UID
// boundary remains the load-bearing control. See spec §4.
// ExecSandboxProfile returns the Seatbelt (sandbox-exec) profile string for a
// terminal-anchored exec child (Option A): allow-by-default, denying byn's own
// state dir + socket (defense in depth atop the _byn-exec UID boundary).
// noNetwork additionally denies all network. The privsep helper applies it via
// `sandbox-exec -p <profile>` AFTER dropping to _byn-exec. Paths are
// symlink-resolved so the Seatbelt deny matches the kernel real path. Returns ""
// when there is nothing to confine, so the helper runs the target directly.
func ExecSandboxProfile(stateDir, socketPath string, noNetwork bool) string {
	sd := resolveSymlinks(stateDir)
	sp := resolveSymlinks(socketPath)
	if sd == "" && sp == "" && !noNetwork {
		return ""
	}
	return seatbeltProfile(SandboxOpts{StateDir: sd, SocketPath: sp, NoNetwork: noNetwork})
}

func seatbeltProfile(opts SandboxOpts) string {
	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(allow default)\n")
	// Deny the child ALL access to byn's state dir (vault, audit, trust store).
	if opts.StateDir != "" {
		fmt.Fprintf(&b, "(deny file* (subpath %q))\n", opts.StateDir)
	}
	// Deny the daemon socket explicitly (belt-and-suspenders; peercred already
	// rejects _byn-exec, but make it unreachable).
	if opts.SocketPath != "" {
		fmt.Fprintf(&b, "(deny file* (literal %q))\n", opts.SocketPath)
		fmt.Fprintf(&b, "(deny network* (literal %q))\n", "unix:"+opts.SocketPath)
	}
	if opts.NoNetwork {
		b.WriteString("(deny network*)\n")
	}
	return b.String()
}
