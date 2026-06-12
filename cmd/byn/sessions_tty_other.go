//go:build !linux && !darwin

package main

// ttyRdev returns 0 on unsupported platforms; callers treat 0 as
// "uid-only binding" (no session file is saved or loaded).
func ttyRdev() int32 { return 0 }
