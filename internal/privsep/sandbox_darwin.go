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
