//go:build !byntest

package main

// forcedUnprovisioned is always false in a shipping build.
//
// There is no env override here, for the same reason defaultDir has none: a
// switch that makes byn forget it is privsep-separated is attack surface. The
// test seam lives in the byntest-tagged twin.
func forcedUnprovisioned() bool { return false }
