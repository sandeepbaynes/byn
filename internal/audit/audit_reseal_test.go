package audit

import (
	"bytes"
	"context"
	"encoding/hex"
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

// reseededChain is the log of a vault that was deleted and re-created under the
// same name: e0..e2 were signed with the OLD vault's seed, and the new vault,
// finding the old log on disk, chained e3.. from e2's recorded head under its
// own seed. Under the current seed every old line fails, not just the first.
func reseededChain(t *testing.T) (*Logger, string) {
	t.Helper()
	l, _, dir := freshLogger(t)
	oldSeed := l.seed
	newSeed := make([]byte, len(oldSeed))
	for i := range newSeed {
		newSeed[i] = ^oldSeed[i]
	}
	l.seed = newSeed // pretend the old vault wrote these
	mustAppend(t, l, "old0")
	mustAppend(t, l, "old1")
	mustAppend(t, l, "old2")
	l.seed = oldSeed // the re-created vault's seed, which is what New() loaded
	mustAppend(t, l, "new3")
	mustAppend(t, l, "new4")
	return l, dir
}

// One reseal covers the whole stretch of old-seed events, and verify reports
// how many were signed off rather than pretending they were checked.
func TestReseal_BridgesAStretchOfOldSeedEvents(t *testing.T) {
	l, dir := reseededChain(t)
	ctx := context.Background()
	r, err := l.Verify(ctx)
	if err != nil || r.BadIndex != 0 || r.Total != 5 {
		t.Fatalf("pre: want break@0 of 5, got %+v err=%v", r, err)
	}
	before := readNewestLog(t, dir)

	m, err := l.Reseal(ctx, "vault re-created", "owner")
	if err != nil {
		t.Fatalf("Reseal: %v", err)
	}
	if m.BrokenIndex != 0 || m.ResumeIndex != 3 {
		t.Fatalf("marker = %+v, want broken 0 resume 3", m)
	}
	r, err = l.Verify(ctx)
	if err != nil || r.BadIndex != -1 || r.Acked != 1 || r.Unverifiable != 3 || r.Total != 6 {
		t.Fatalf("post: want intact, 1 acked, 3 unverifiable of 6, got %+v err=%v", r, err)
	}
	if after := readNewestLog(t, dir); !bytes.HasPrefix(after, before) {
		t.Error("reseal rewrote existing log bytes — must only append")
	}
	// Life goes on: later events chain from the marker as usual.
	mustAppend(t, l, "new6")
	if r, err := l.Verify(ctx); err != nil || r.BadIndex != -1 || r.Total != 7 {
		t.Fatalf("after another append: %+v err=%v", r, err)
	}
}

// A marker written before ResumeIndex existed bridges one event, as it always
// did; the next reseal then covers what remains.
func TestReseal_OldSingleEventMarkerStillHonoured(t *testing.T) {
	l, dir := reseededChain(t)
	ctx := context.Background()
	m, err := l.Reseal(ctx, "first try", "owner")
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite the marker as the old format would have written it: no range.
	m.ResumeIndex = 0
	lines := bytes.Split(bytes.TrimRight(readNewestLog(t, dir), "\n"), []byte("\n"))
	var marker Event
	if err := json.Unmarshal(lines[len(lines)-1], &marker); err != nil {
		t.Fatal(err)
	}
	marker.Reseal = m
	// Re-sign it under the current seed, chained as it was.
	var prevEv Event
	if err := json.Unmarshal(lines[len(lines)-2], &prevEv); err != nil {
		t.Fatal(err)
	}
	prev, _ := hex.DecodeString(prevEv.HMACChain)
	h, err := computeWithSeed(l.seed, prev, marker)
	if err != nil {
		t.Fatal(err)
	}
	marker.HMACChain = hex.EncodeToString(h)
	l.prevHex = marker.HMACChain
	line, _ := json.Marshal(marker)
	lines[len(lines)-1] = line
	if err := os.WriteFile(newestLogFile(t, dir), append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := l.Verify(ctx)
	if err != nil || r.BadIndex != 1 || r.Acked != 1 || r.Unverifiable != 1 {
		t.Fatalf("old-format marker: want break@1 after bridging one event, got %+v err=%v", r, err)
	}
	m2, err := l.Reseal(ctx, "second try", "owner")
	if err != nil {
		t.Fatal(err)
	}
	if m2.BrokenIndex != 1 || m2.ResumeIndex != 3 {
		t.Fatalf("second marker = %+v, want broken 1 resume 3", m2)
	}
	if r, err := l.Verify(ctx); err != nil || r.BadIndex != -1 || r.Acked != 2 || r.Unverifiable != 3 {
		t.Fatalf("after second reseal: %+v err=%v", r, err)
	}
}

// A single-point break — one event chained from a stale head, everything after
// it consistent — is still bridged one event wide.
func TestReseal_SinglePointBreakResumesAtNext(t *testing.T) {
	l, _, _ := brokenChain(t)
	m, err := l.Reseal(context.Background(), "crash", "owner")
	if err != nil {
		t.Fatal(err)
	}
	if m.BrokenIndex != 3 || m.ResumeIndex != 4 {
		t.Fatalf("marker = %+v, want broken 3 resume 4", m)
	}
	if r, err := l.Verify(context.Background()); err != nil || r.BadIndex != -1 || r.Unverifiable != 1 {
		t.Fatalf("%+v err=%v", r, err)
	}
}
