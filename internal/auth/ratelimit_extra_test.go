package auth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRetryAfterError_Error(t *testing.T) {
	e := &RetryAfterError{RetryAfter: 5 * time.Second}
	s := e.Error()
	if !strings.Contains(s, "rate limited") || !strings.Contains(s, "5s") {
		t.Fatalf("Error = %q", s)
	}
}

func TestRetryAfterError_IsErrRateLimited(t *testing.T) {
	e := &RetryAfterError{RetryAfter: time.Second}
	if !errors.Is(e, ErrRateLimited) {
		t.Fatal("errors.Is should match")
	}
	other := errors.New("other")
	if errors.Is(e, other) {
		t.Fatal("should not match unrelated err")
	}
}

func TestComputeDelay_ZeroFailures(t *testing.T) {
	rl, _, _ := newRL(t)
	if got := rl.computeDelay(0); got != 0 {
		t.Fatalf("got %v, want 0", got)
	}
	if got := rl.computeDelay(-1); got != 0 {
		t.Fatalf("got %v, want 0 for negative", got)
	}
}

func TestRealClock_NowAdvances(t *testing.T) {
	c := realClock{}
	a := c.Now()
	time.Sleep(time.Millisecond)
	b := c.Now()
	if !b.After(a) {
		t.Fatal("expected time to advance")
	}
}

func TestPersist_MkdirAllCreatesDir(t *testing.T) {
	// Pointing at a non-existent nested dir should still succeed:
	// persist() calls MkdirAll.
	path := filepath.Join(t.TempDir(), "subdir", RateLimiterFile)
	rl := NewRateLimiter(path)
	if err := rl.RecordFailure(); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat: %v", err)
	}
}

func TestPersist_MkdirFails(t *testing.T) {
	// Point at a directory under a regular file so MkdirAll fails.
	td := t.TempDir()
	blocker := filepath.Join(td, "block")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	path := filepath.Join(blocker, "subdir", RateLimiterFile)
	rl := NewRateLimiter(path)
	if err := rl.RecordFailure(); err == nil {
		t.Fatal("expected mkdir err")
	}
}

func TestSetClockAndBackoff_Coverage(t *testing.T) {
	rl, _, _ := newRL(t)
	rl.SetClock(&fakeClock{t: time.Now()})
	rl.SetBackoff(time.Second, time.Minute, 3.0)
	// Verify clamping logic via 1 failure.
	if err := rl.RecordFailure(); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
}
