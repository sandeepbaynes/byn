//go:build darwin || linux

package secmem

import "golang.org/x/sys/unix"

// lockMemory pins the pages backing b in physical memory, preventing
// the OS from swapping them to disk. Returns the underlying error
// from mlock(2) on failure.
//
// Common failure modes:
//
//   - ENOMEM: per-process or system-wide mlock budget exhausted
//     (RLIMIT_MEMLOCK). On Linux the default is 64 KiB per process;
//     on macOS unlimited for the calling user.
//   - EAGAIN: similar resource pressure.
//
// Failure is non-fatal for the caller — Buffer still wipes contents
// on release; only the swap-resistance guarantee is lost.
func lockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Mlock(b)
}

// unlockMemory reverses lockMemory.
func unlockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Munlock(b)
}
