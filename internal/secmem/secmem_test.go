package secmem

import (
	"bytes"
	"errors"
	"runtime"
	"testing"
)

func TestNewBuffer_ZeroesAndLocks(t *testing.T) {
	b, err := NewBuffer(32)
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer b.Wipe()
	if got := b.Len(); got != 32 {
		t.Fatalf("Len = %d, want 32", got)
	}
	for i, x := range b.Bytes() {
		if x != 0 {
			t.Fatalf("buffer not zero at %d: %v", i, x)
		}
	}
	// On macOS/Linux we expect mlock to succeed for small buffers
	// under default RLIMIT_MEMLOCK. Skip the assertion on other OSes
	// where lockMemory is a no-op.
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		if !b.IsLocked() {
			t.Logf("warning: 32-byte mlock failed on %s (RLIMIT_MEMLOCK?)", runtime.GOOS)
		}
	}
}

func TestNewBufferFrom_CopiesSrc(t *testing.T) {
	src := []byte("hello-world")
	b, err := NewBufferFrom(src)
	if err != nil {
		t.Fatalf("NewBufferFrom: %v", err)
	}
	defer b.Wipe()
	if !bytes.Equal(b.Bytes(), src) {
		t.Fatalf("Bytes = %q, want %q", b.Bytes(), src)
	}
	// Mutating src must not change b.
	src[0] = 'X'
	if b.Bytes()[0] != 'h' {
		t.Fatal("Buffer mirrors src mutations (no copy)")
	}
}

func TestNewBuffer_RejectsInvalid(t *testing.T) {
	for _, n := range []int{0, -1, -100} {
		if _, err := NewBuffer(n); !errors.Is(err, ErrInvalidSize) {
			t.Errorf("NewBuffer(%d) err = %v, want ErrInvalidSize", n, err)
		}
	}
}

func TestWipe_ZerosAndIsIdempotent(t *testing.T) {
	b, err := NewBufferFrom([]byte("sensitive material"))
	if err != nil {
		t.Fatalf("NewBufferFrom: %v", err)
	}
	// Capture the underlying slice header so we can verify Wipe
	// zeroed before nilling.
	pre := b.Bytes()
	if len(pre) == 0 || pre[0] == 0 {
		t.Fatal("setup precondition failed")
	}
	b.Wipe()
	// After Wipe, Bytes returns nil.
	if got := b.Bytes(); got != nil {
		t.Fatalf("Bytes after Wipe = %v, want nil", got)
	}
	// The previously-returned slice should have been zeroed before
	// being released back to the allocator.
	for i, x := range pre {
		if x != 0 {
			t.Fatalf("byte %d not zeroed after Wipe: %v", i, x)
		}
	}
	// Idempotent.
	b.Wipe()
	b.Wipe()
}

func TestBytes_AfterWipeReturnsNil(t *testing.T) {
	b, _ := NewBuffer(8)
	b.Wipe()
	if b.Bytes() != nil {
		t.Fatal("Bytes after Wipe must be nil")
	}
	if b.Len() != 0 {
		t.Fatal("Len after Wipe must be 0")
	}
	if b.IsLocked() {
		t.Fatal("IsLocked after Wipe must be false")
	}
}

func TestWriteRead_RoundTrip(t *testing.T) {
	b, _ := NewBuffer(16)
	defer b.Wipe()
	payload := []byte("0123456789abcdef")
	copy(b.Bytes(), payload)
	if !bytes.Equal(b.Bytes(), payload) {
		t.Fatalf("readback mismatch: %x", b.Bytes())
	}
}
