//go:build !unix

package main

import "os"

// verifyOwnedBy is a no-op on non-unix platforms — `byn setup` cannot provision
// privsep there (the privsep primitives return ErrUnsupported before this runs),
// so the ownership post-condition never executes for real. The stub keeps the
// package compiling on every platform.
func verifyOwnedBy(_ os.FileInfo, _, _ int) error { return nil }
