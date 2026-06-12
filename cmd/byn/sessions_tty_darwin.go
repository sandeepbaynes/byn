//go:build darwin

package main

import (
	"os"
	"syscall"
)

// ttyRdev returns the controlling terminal's rdev (device number) by opening
// /dev/tty. Returns 0 if the process has no controlling terminal (piped/
// non-interactive) or if stat fails. On Darwin, Rdev is int32 (Tdev).
func ttyRdev() int32 {
	f, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return 0
	}
	return int32(st.Rdev) //nolint:gosec // G115: Rdev is int32 on Darwin (Tdev)
}
