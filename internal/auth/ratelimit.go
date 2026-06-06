package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RateLimiterFile is the on-disk JSON file that holds per-actor
// backoff state. Persisted so killing the daemon doesn't reset the
// backoff.
const RateLimiterFile = "auth-state.json"

// Defaults aim to add tens of seconds of friction after a handful of
// wrong guesses without locking real users out of their own laptops.
var (
	// DefaultBackoffBase is the first delay applied after one failure.
	DefaultBackoffBase = 500 * time.Millisecond
	// DefaultBackoffMax caps the per-attempt delay.
	DefaultBackoffMax = 5 * time.Minute
	// DefaultBackoffMultiplier doubles the delay each consecutive
	// failure: 0.5s → 1s → 2s → 4s → ...
	DefaultBackoffMultiplier = 2.0
	// DefaultLockoutAttempts caps consecutive failures before the
	// limiter switches from "wait then retry" to "always denied
	// until human resets via byn auth reset". Set high enough
	// that genuine typos don't trip it.
	DefaultLockoutAttempts = 0 // 0 = no permanent lockout in this slice
)

// Clock is the time source. Override in tests.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// ErrRateLimited indicates the caller must wait at least RetryAfter
// before another attempt.
var ErrRateLimited = errors.New("auth: rate limited")

// RetryAfterError is returned when a request is denied due to
// backoff. RetryAfter is the remaining cooldown.
type RetryAfterError struct {
	RetryAfter time.Duration
}

func (e *RetryAfterError) Error() string {
	return fmt.Sprintf("auth: rate limited; retry after %s", e.RetryAfter.Round(time.Second))
}

// Is implements errors.Is so callers can match the typed
// RetryAfterError against the sentinel ErrRateLimited.
func (e *RetryAfterError) Is(target error) bool { return target == ErrRateLimited }

// RateLimiter throttles repeated failures, persisting state to a
// JSON file under the vault directory.
//
// A single global "actor" key is used in this slice — the daemon is
// single-user. Phase 7 enterprise will key by user.
type RateLimiter struct {
	path  string
	clock Clock

	base       time.Duration
	max        time.Duration
	multiplier float64

	mu    sync.Mutex
	state limiterState
}

type limiterState struct {
	Failures      int       `json:"failures"`        // consecutive failure count
	NextAttemptAt time.Time `json:"next_attempt_at"` // wall-clock time of next allowed attempt
}

// NewRateLimiter creates a RateLimiter backed by path. The file is
// created on first Record* call if it doesn't exist; corrupt or
// unreadable state is treated as a clean slate and overwritten.
func NewRateLimiter(path string) *RateLimiter {
	rl := &RateLimiter{
		path:       path,
		clock:      realClock{},
		base:       DefaultBackoffBase,
		max:        DefaultBackoffMax,
		multiplier: DefaultBackoffMultiplier,
	}
	rl.load()
	return rl
}

// SetClock swaps the time source. Use only from tests.
func (r *RateLimiter) SetClock(c Clock) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clock = c
}

// SetBackoff overrides default base / max / multiplier. Use from
// tests or configuration.
func (r *RateLimiter) SetBackoff(base, maxDelay time.Duration, multiplier float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.base = base
	r.max = maxDelay
	r.multiplier = multiplier
}

// Check returns nil if an attempt is allowed right now, or a
// *RetryAfterError if the caller must wait.
func (r *RateLimiter) Check() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock.Now()
	if now.Before(r.state.NextAttemptAt) {
		return &RetryAfterError{RetryAfter: r.state.NextAttemptAt.Sub(now)}
	}
	return nil
}

// RecordSuccess clears the failure counter and persists.
func (r *RateLimiter) RecordSuccess() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state.Failures = 0
	r.state.NextAttemptAt = time.Time{}
	return r.persist()
}

// RecordFailure increments the failure counter, computes the new
// backoff window, and persists.
func (r *RateLimiter) RecordFailure() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state.Failures++
	delay := r.computeDelay(r.state.Failures)
	r.state.NextAttemptAt = r.clock.Now().Add(delay)
	return r.persist()
}

// Failures returns the current consecutive-failure count.
func (r *RateLimiter) Failures() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state.Failures
}

// computeDelay returns base * multiplier^(failures-1), clamped to
// max. Caller holds the lock.
func (r *RateLimiter) computeDelay(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	delay := float64(r.base)
	for i := 1; i < failures; i++ {
		delay *= r.multiplier
		if time.Duration(delay) >= r.max {
			return r.max
		}
	}
	if time.Duration(delay) > r.max {
		return r.max
	}
	return time.Duration(delay)
}

// load reads state from disk. Errors are non-fatal: a corrupt or
// missing file means "no prior state".
func (r *RateLimiter) load() {
	data, err := os.ReadFile(r.path) // #nosec G304 -- caller-controlled path
	if err != nil {
		return
	}
	var s limiterState
	if err := json.Unmarshal(data, &s); err != nil {
		return
	}
	r.state = s
}

// persist writes state via atomic rename. Caller holds the lock.
func (r *RateLimiter) persist() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return fmt.Errorf("auth: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(r.path), ".auth-state-*")
	if err != nil {
		return fmt.Errorf("auth: tempfile: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("auth: chmod: %w", err)
	}
	if err := json.NewEncoder(tmp).Encode(r.state); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("auth: encode: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("auth: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("auth: close: %w", err)
	}
	return os.Rename(tmpPath, r.path)
}
