package main

import (
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// TestWatchClientTimeout_OutlivesTheWaitItAsksFor is named after the live
// failure it prevents.
//
// A watch is a single IPC round-trip lasting as long as the wait. The client
// caps a round-trip at 60 seconds, so the first real watch died at exactly
// 60.040s with "ipc: read: i/o timeout" — while the approval it was waiting for
// had been recorded correctly. The answer arrived and there was nobody on the
// line.
//
// The integration test did not catch it because the decision came back in under
// a second, so the wait never approached the cap. Two constants in two packages
// had to agree and nothing checked that they did. This checks it.
func TestWatchClientTimeout_OutlivesTheWaitItAsksFor(t *testing.T) {
	for _, seconds := range []int{1, 30, 60, defaultWatchSeconds, maxWatchSeconds, maxWatchSeconds * 2} {
		got := watchClientTimeout(seconds)
		wait := time.Duration(min(seconds, maxWatchSeconds)) * time.Second
		if got <= wait {
			t.Errorf("a %ds watch holds the connection %s — the client hangs up before "+
				"the daemon answers, and a real decision is lost to a transport error", seconds, got)
		}
		if got <= ipc.DefaultClientTimeout && wait >= ipc.DefaultClientTimeout {
			t.Errorf("a %ds watch must override the %s default round-trip cap, got %s",
				seconds, ipc.DefaultClientTimeout, got)
		}
	}
}

// The daemon's ceiling and the CLI's must not drift apart: if the CLI let a
// caller ask for longer than the daemon will hold, it would hang up early again
// for exactly the same reason, only at a different number.
func TestWatchClientTimeout_IsBoundedLikeTheDaemon(t *testing.T) {
	huge := watchClientTimeout(999999)
	if huge > time.Duration(maxWatchSeconds)*time.Second+watchTimeoutSlack {
		t.Fatalf("client wait %s exceeds the daemon ceiling plus slack", huge)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
