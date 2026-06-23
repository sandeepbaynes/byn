package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestNew_ReconcilesHeadLagFromDisk: a SIGTERM/crash between the on-disk write
// and the meta-head update leaves meta one entry behind. New() must trust the
// durable on-disk last line, re-persist the head, and let the next Append chain
// intact — the documented-but-previously-missing repair (audit.go header).
func TestNew_ReconcilesHeadLagFromDisk(t *testing.T) {
	l, store, dir := freshLogger(t)
	ctx := context.Background()
	if _, err := l.Append(ctx, Event{Op: "put", Outcome: OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	h2, err := l.Append(ctx, Event{Op: "get", Outcome: OutcomeOK})
	if err != nil {
		t.Fatal(err)
	}
	last, err := l.Append(ctx, Event{Op: "del", Outcome: OutcomeOK})
	if err != nil {
		t.Fatal(err)
	}

	// On-disk last line holds `last`; pretend the meta update for it never landed.
	if err := store.MetaSet(ctx, MetaKeyHead, h2); err != nil {
		t.Fatal(err)
	}

	l2, err := New(ctx, dir, "vault-uuid-test", "default", store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if l2.Head() != last {
		t.Fatalf("head not reconciled to disk: got %s want %s", l2.Head(), last)
	}
	if hd, _ := store.MetaGet(ctx, MetaKeyHead); hd != last {
		t.Errorf("meta head not re-persisted: got %s want %s", hd, last)
	}
	if _, err := l2.Append(ctx, Event{Op: "put", Outcome: OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	if bad, total, _, err := l2.VerifyChain(ctx); err != nil || bad != -1 {
		t.Fatalf("chain should be intact after reconcile: bad=%d total=%d err=%v", bad, total, err)
	}
}

// TestNew_ConsistentHead_NoReconcile: when meta head already matches the on-disk
// last line, New() must NOT rewrite meta.
func TestNew_ConsistentHead_NoReconcile(t *testing.T) {
	l, store, dir := freshLogger(t)
	ctx := context.Background()
	if _, err := l.Append(ctx, Event{Op: "put", Outcome: OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	before := store.setCount
	l2, err := New(ctx, dir, "vault-uuid-test", "default", store)
	if err != nil {
		t.Fatal(err)
	}
	if store.setCount != before {
		t.Errorf("New wrote meta %d time(s) when head already matched disk", store.setCount-before)
	}
	if l2.Head() != l.Head() {
		t.Errorf("head changed unexpectedly: %s vs %s", l2.Head(), l.Head())
	}
}

// TestNew_EmptyLog_NoHead: a fresh vault with no events has an empty head.
func TestNew_EmptyLog_NoHead(t *testing.T) {
	_, store, dir := freshLogger(t) // freshLogger appends nothing
	ctx := context.Background()
	l2, err := New(ctx, dir, "vault-uuid-test", "default", store)
	if err != nil {
		t.Fatal(err)
	}
	if l2.Head() != "" {
		t.Errorf("empty log should have empty head, got %q", l2.Head())
	}
}

// TestNew_TornTrailingLine_WalksBack: a partial trailing write (crash mid-line)
// must not abort New — it reconciles to the last PARSEABLE line.
func TestNew_TornTrailingLine_WalksBack(t *testing.T) {
	l, store, dir := freshLogger(t)
	ctx := context.Background()
	if _, err := l.Append(ctx, Event{Op: "put", Outcome: OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	good, err := l.Append(ctx, Event{Op: "get", Outcome: OutcomeOK})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(newestLogFile(t, dir), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"ts":123,"op":"par`); err != nil { // torn, unparseable
		t.Fatal(err)
	}
	_ = f.Close()

	if err := store.MetaSet(ctx, MetaKeyHead, ""); err != nil { // force reconcile from disk
		t.Fatal(err)
	}
	l2, err := New(ctx, dir, "vault-uuid-test", "default", store)
	if err != nil {
		t.Fatalf("New must tolerate a torn trailing line: %v", err)
	}
	if l2.Head() != good {
		t.Errorf("torn trailing line: head should be last parseable line %s, got %s", good, l2.Head())
	}
}

// newestLogFile returns the newest YYYY-MM.log path in the vault's audit dir.
func newestLogFile(t *testing.T, dir string) string {
	t.Helper()
	adir := filepath.Join(dir, "audit", "default")
	ents, err := os.ReadDir(adir)
	if err != nil {
		t.Fatal(err)
	}
	var name string
	for _, e := range ents {
		if !e.IsDir() && e.Name() > name {
			name = e.Name()
		}
	}
	if name == "" {
		t.Fatal("no log file written")
	}
	return filepath.Join(adir, name)
}
