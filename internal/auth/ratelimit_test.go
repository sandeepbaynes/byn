package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.t = c.t.Add(d)
}

func newRL(t *testing.T) (*RateLimiter, *fakeClock, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), RateLimiterFile)
	rl := NewRateLimiter(path)
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	rl.SetClock(clk)
	// Tighter defaults for fast tests.
	rl.SetBackoff(100*time.Millisecond, 10*time.Second, 2.0)
	return rl, clk, path
}

func TestCheck_CleanState(t *testing.T) {
	rl, _, _ := newRL(t)
	if err := rl.Check(); err != nil {
		t.Fatalf("Check on clean limiter: %v", err)
	}
}

func TestRecordFailure_BackoffDoubles(t *testing.T) {
	rl, clk, _ := newRL(t)

	for i := 1; i <= 5; i++ {
		if err := rl.RecordFailure(); err != nil {
			t.Fatalf("RecordFailure %d: %v", i, err)
		}
		err := rl.Check()
		var rae *RetryAfterError
		if !errors.As(err, &rae) {
			t.Fatalf("after %d failures: err = %v, want RetryAfterError", i, err)
		}
		// Computed delay: 100ms * 2^(i-1), clamped to 10s.
		want := time.Duration(100*int64(1<<(i-1))) * time.Millisecond
		if want > 10*time.Second {
			want = 10 * time.Second
		}
		if rae.RetryAfter > want+10*time.Millisecond || rae.RetryAfter < want-10*time.Millisecond {
			t.Fatalf("attempt %d: RetryAfter = %s, want ≈ %s", i, rae.RetryAfter, want)
		}
		// Advance past the delay so the next failure starts cleanly.
		clk.advance(want + time.Millisecond)
	}
}

func TestCheck_WithinBackoff(t *testing.T) {
	rl, clk, _ := newRL(t)
	if err := rl.RecordFailure(); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if err := rl.Check(); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Check during backoff: err = %v, want ErrRateLimited", err)
	}
	clk.advance(50 * time.Millisecond)
	if err := rl.Check(); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Check still during backoff: err = %v, want ErrRateLimited", err)
	}
	clk.advance(60 * time.Millisecond) // total 110ms past failure → past 100ms backoff
	if err := rl.Check(); err != nil {
		t.Fatalf("Check after backoff window: %v", err)
	}
}

func TestRecordSuccess_ResetsFailures(t *testing.T) {
	rl, clk, _ := newRL(t)
	for i := 0; i < 3; i++ {
		_ = rl.RecordFailure()
		clk.advance(time.Second)
	}
	if got := rl.Failures(); got != 3 {
		t.Fatalf("Failures = %d, want 3", got)
	}
	if err := rl.RecordSuccess(); err != nil {
		t.Fatalf("RecordSuccess: %v", err)
	}
	if got := rl.Failures(); got != 0 {
		t.Fatalf("Failures after success = %d, want 0", got)
	}
	if err := rl.Check(); err != nil {
		t.Fatalf("Check after success: %v", err)
	}
}

func TestPersistence_AcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), RateLimiterFile)
	rl := NewRateLimiter(path)
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	rl.SetClock(clk)
	rl.SetBackoff(100*time.Millisecond, 10*time.Second, 2.0)
	for i := 0; i < 3; i++ {
		_ = rl.RecordFailure()
		clk.advance(time.Second)
	}

	// New instance reads the same file.
	rl2 := NewRateLimiter(path)
	rl2.SetClock(clk)
	rl2.SetBackoff(100*time.Millisecond, 10*time.Second, 2.0)
	if got := rl2.Failures(); got != 3 {
		t.Fatalf("Failures after reload = %d, want 3", got)
	}
}

func TestPersistence_FileExistsWithMode0600(t *testing.T) {
	_, _, path := newRL(t)
	rl := NewRateLimiter(path)
	if err := rl.RecordFailure(); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("state file mode = %o, want 0600", got)
	}
}

func TestPersistence_CorruptFileTreatedAsClean(t *testing.T) {
	path := filepath.Join(t.TempDir(), RateLimiterFile)
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rl := NewRateLimiter(path)
	if got := rl.Failures(); got != 0 {
		t.Fatalf("Failures with corrupt state = %d, want 0", got)
	}
	if err := rl.Check(); err != nil {
		t.Fatalf("Check with corrupt state: %v", err)
	}
}

func TestPersistence_MissingFileTreatedAsClean(t *testing.T) {
	rl := NewRateLimiter(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if got := rl.Failures(); got != 0 {
		t.Fatalf("Failures with missing state = %d, want 0", got)
	}
}

func TestBackoff_HitsMaxClamp(t *testing.T) {
	rl, _, _ := newRL(t)
	for i := 0; i < 20; i++ {
		_ = rl.RecordFailure()
	}
	err := rl.Check()
	var rae *RetryAfterError
	if !errors.As(err, &rae) {
		t.Fatalf("err = %v, want RetryAfterError", err)
	}
	if rae.RetryAfter != 10*time.Second {
		t.Fatalf("RetryAfter = %s, want 10s clamp", rae.RetryAfter)
	}
}
