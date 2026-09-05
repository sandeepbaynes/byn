//go:build !linux && !darwin

package main

// snapshotProcs has no implementation on platforms where byn cannot read the
// process table; the kill path degrades to signalling the named pid alone.
func snapshotProcs() []procEntry { return nil }
