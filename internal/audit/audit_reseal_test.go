package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func mustAppend(t *testing.T, l *Logger, op string) string {
	t.Helper()
	h, err := l.Append(context.Background(), Event{Op: op, Outcome: OutcomeOK})
	if err != nil {
		t.Fatalf("append %s: %v", op, err)
	}
	return h
}

// brokenChain builds a log with a genuine break at index 3: e0..e2 are intact,
// e3 is chained from e1's head (the head-lag artifact — a stale head loaded after
// a crash without reconciliation), and e4 is consistent with e3.
func brokenChain(t *testing.T) (*Logger, *fakeStore, string) {
	t.Helper()
	l, store, dir := freshLogger(t)
	mustAppend(t, l, "e0")
	h1 := mustAppend(t, l, "e1")
	mustAppend(t, l, "e2")
	l.prevHex = h1 // simulate a restart that loaded a stale head (pre-reconcile)
	mustAppend(t, l, "e3")
	mustAppend(t, l, "e4")
	return l, store, dir
}

func TestReseal_NoBreak(t *testing.T) {
	l, _, _ := freshLogger(t)
	mustAppend(t, l, "put")
	if _, err := l.Reseal(context.Background(), "x", "owner"); !errors.Is(err, ErrNoBreak) {
		t.Fatalf("intact chain: want ErrNoBreak, got %v", err)
	}
}

func TestReseal_ClearsBreak(t *testing.T) {
	l, _, dir := brokenChain(t)
	ctx := context.Background()
	if bad, _, acked, err := l.VerifyChain(ctx); err != nil || bad != 3 || acked != 0 {
		t.Fatalf("pre: want break@3 acked0, got bad=%d acked=%d err=%v", bad, acked, err)
	}
	before := readNewestLog(t, dir)

	m, err := l.Reseal(ctx, "daemon restart during testing", "owner")
	if err != nil {
		t.Fatalf("Reseal: %v", err)
	}
	if m.BrokenIndex != 3 {
		t.Errorf("marker broken_index=%d want 3", m.BrokenIndex)
	}
	if bad, _, acked, err := l.VerifyChain(ctx); err != nil || bad != -1 || acked != 1 {
		t.Fatalf("post: want intact acked1, got bad=%d acked=%d err=%v", bad, acked, err)
	}
	// Reseal must only APPEND — the original event bytes are untouched.
	if after := readNewestLog(t, dir); !bytes.HasPrefix(after, before) {
		t.Error("reseal rewrote existing log bytes — must only append")
	}
}

// TestReseal_ForgedMarkerRejected: a marker an attacker forges WITHOUT the seed
// cannot clear a break. The expected head it would need to record is itself
// seed-derived, so a forged marker carries a wrong expected_head and pass 2
// refuses to honor it.
func TestReseal_ForgedMarkerRejected(t *testing.T) {
	l, _, dir := brokenChain(t)
	ctx := context.Background()
	bad, _, _, _ := l.VerifyChain(ctx)
	observed := nthEventHash(t, dir, bad)
	forged := Event{
		Op: "audit.reseal", Outcome: OutcomeOK, HMACChain: "deadbeef", // bogus signature
		Reseal: &ResealMarker{
			BrokenIndex: bad, ObservedHead: observed, ExpectedHead: "00", // not seed-derivable
			Reason: "evil", By: "attacker",
		},
	}
	appendRawLine(t, dir, forged)
	if bad2, _, acked, _ := l.VerifyChain(ctx); bad2 < 0 {
		t.Fatalf("forged marker must NOT clear the break (got intact, acked=%d)", acked)
	}
}

// TestReseal_OrdinaryEventsUnaffected: a non-marker event omits the reseal key.
func TestReseal_OrdinaryEventsUnaffected(t *testing.T) {
	l, _, dir := freshLogger(t)
	mustAppend(t, l, "put")
	if bytes.Contains(readNewestLog(t, dir), []byte(`"reseal"`)) {
		t.Error("an ordinary event must not serialize a reseal field")
	}
}

func readNewestLog(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(newestLogFile(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func nthEventHash(t *testing.T, dir string, n int) string {
	t.Helper()
	lines := bytes.Split(bytes.TrimRight(readNewestLog(t, dir), "\n"), []byte("\n"))
	if n < 0 || n >= len(lines) {
		t.Fatalf("event %d out of range (%d lines)", n, len(lines))
	}
	var e Event
	if err := json.Unmarshal(lines[n], &e); err != nil {
		t.Fatal(err)
	}
	return e.HMACChain
}

func appendRawLine(t *testing.T, dir string, e Event) {
	t.Helper()
	line, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(newestLogFile(t, dir), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
}
