//go:build !darwin && !linux

package secmem

// lockMemory is a no-op on non-Unix platforms. The buffer is still
// zeroed at Wipe time; only the swap-resistance guarantee is
// unavailable.
func lockMemory(_ []byte) error { return nil }

// unlockMemory mirrors lockMemory.
func unlockMemory(_ []byte) error { return nil }
