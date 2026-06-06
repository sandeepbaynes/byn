// Package secmem provides byte buffers that resist accidental
// exposure: pages are locked into RAM (via mlock(2) where supported)
// so the kernel won't swap them, and Wipe overwrites their contents
// with zeros before release.
//
// This is best-effort, not a defense against a kernel-level attacker
// or a hostile process running as the same UID. Specifically it does
// NOT defend against:
//
//   - core dumps (use setrlimit RLIMIT_CORE = 0 elsewhere)
//   - hibernation (writes RAM to disk; OS-level concern)
//   - debuggers attached to the process
//   - GC scans of the underlying byte slice (the slice still moves
//     through normal Go allocator paths, just with mlock applied)
//
// What it DOES give you:
//
//   - the pages are mlocked, so they won't be swapped to disk in
//     normal operation
//   - the buffer is zeroed at Wipe time before any release
//   - clear API discipline: anything that holds secret material
//     uses a *Buffer instead of a raw []byte, so reviewers can
//     spot the boundary
//
// Usage:
//
//	buf, err := secmem.NewBuffer(32)
//	if err != nil { ... }
//	defer buf.Wipe()
//	copy(buf.Bytes(), wrappedKey)
//	// ...use buf.Bytes()...
package secmem

import (
	"errors"
	"sync"
)

// Buffer is a byte slice with extra hygiene: pages are mlocked where
// supported, Wipe overwrites contents with zeros, and the Bytes
// accessor returns the same backing array for the lifetime of the
// Buffer (so callers can hand it to crypto routines that don't take
// a copy).
//
// All methods are safe for concurrent reads of Bytes after a single
// initial Wipe-or-write. Concurrent mutation is the caller's
// responsibility — secmem provides physical isolation, not logical
// synchronization.
type Buffer struct {
	mu     sync.Mutex
	data   []byte
	locked bool // true if mlock succeeded (best-effort)
}

// ErrInvalidSize is returned by NewBuffer when size is non-positive.
var ErrInvalidSize = errors.New("secmem: size must be positive")

// NewBuffer allocates a Buffer of the given size. The buffer is
// zero-filled and the underlying pages are mlocked if the platform
// supports it (mlock failure is non-fatal and logged via the second
// return value). On a successful return, the buffer must eventually
// be Wipe()d by the caller.
func NewBuffer(size int) (*Buffer, error) {
	if size <= 0 {
		return nil, ErrInvalidSize
	}
	b := &Buffer{data: make([]byte, size)}
	// mlock is platform-specific; the OS-tagged file implements
	// lockMemory. Failure is non-fatal — we still wipe on release.
	b.locked = lockMemory(b.data) == nil
	return b, nil
}

// NewBufferFrom allocates a Buffer and copies src into it. src is not
// retained; callers may zero it after this returns.
func NewBufferFrom(src []byte) (*Buffer, error) {
	b, err := NewBuffer(len(src))
	if err != nil {
		return nil, err
	}
	copy(b.data, src)
	return b, nil
}

// Bytes returns the underlying byte slice. The slice is valid until
// Wipe is called; callers MUST NOT retain references past Wipe.
//
// Mutating the returned slice mutates the secured buffer (intended —
// callers often pass it to AEAD Open/Seal as the destination).
func (b *Buffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data
}

// Len returns the buffer's size. Safe to call after Wipe (returns 0).
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.data)
}

// IsLocked reports whether mlock succeeded for this buffer's pages.
// False means the buffer is still zeroed on Wipe, but the OS may
// swap its pages to disk under memory pressure.
func (b *Buffer) IsLocked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.locked
}

// Wipe overwrites the buffer contents with zeros and unlocks the
// pages. The buffer must not be used after Wipe. Idempotent.
func (b *Buffer) Wipe() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.data == nil {
		return
	}
	// Zero before unlocking — once unlocked, the pages may go to
	// swap before we get to overwrite them.
	for i := range b.data {
		b.data[i] = 0
	}
	if b.locked {
		_ = unlockMemory(b.data)
		b.locked = false
	}
	b.data = nil
}
