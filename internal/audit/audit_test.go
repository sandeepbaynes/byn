package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sandeepbaynes/byn/internal/vault"
)

// fakeStore implements chainHeadStore for tests.
type fakeStore struct {
	mu       sync.Mutex
	data     map[string]string
	setCount int // number of MetaSet calls — lets tests assert no redundant writes
}

func newFakeStore(seed []byte) *fakeStore {
	return &fakeStore{data: map[string]string{
		MetaKeySeed: hex.EncodeToString(seed),
	}}
}

func (f *fakeStore) MetaGet(_ context.Context, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data[key], nil
}

func (f *fakeStore) MetaSet(_ context.Context, key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCount++
	f.data[key] = value
	return nil
}

func freshLogger(t *testing.T) (*Logger, *fakeStore, string) {
	t.Helper()
	var seed [32]byte
	_, _ = rand.Read(seed[:])
	store := newFakeStore(seed[:])
	dir := t.TempDir()
	l, err := New(context.Background(), dir, "vault-uuid-test", "default", store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l, store, dir
}

// TestMetaKeysMatchVaultExports guards against drift between the
// audit package's MetaKey constants and the vault package's exports.
// If this fails, the daemon would set the seed under one key and the
// audit logger would look for it under another.
func TestMetaKeysMatchVaultExports(t *testing.T) {
	if MetaKeySeed != vault.MetaKeyAuditChainSeed {
		t.Errorf("MetaKeySeed = %q, vault.MetaKeyAuditChainSeed = %q (drift!)",
			MetaKeySeed, vault.MetaKeyAuditChainSeed)
	}
	if MetaKeyHead != vault.MetaKeyAuditChainHead {
		t.Errorf("MetaKeyHead = %q, vault.MetaKeyAuditChainHead = %q (drift!)",
			MetaKeyHead, vault.MetaKeyAuditChainHead)
	}
}

func TestAppend_WritesLineAndUpdatesHead(t *testing.T) {
	l, store, dir := freshLogger(t)

	head1, err := l.Append(context.Background(), Event{Op: "test", Outcome: OutcomeOK})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if head1 == "" {
		t.Fatal("Head empty after Append")
	}
	got, _ := store.MetaGet(context.Background(), MetaKeyHead)
	if got != head1 {
		t.Fatalf("store head = %q, want %q", got, head1)
	}

	files, _ := filepath.Glob(filepath.Join(dir, "audit", "default", "*.log"))
	if len(files) != 1 {
		t.Fatalf("expected 1 log file, got %v", files)
	}
	info, _ := os.Stat(files[0])
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("audit file mode = %o, want 0600", mode)
	}
}

func TestAppend_ChainsAcrossEvents(t *testing.T) {
	l, _, _ := freshLogger(t)
	var prev string
	for i := 0; i < 5; i++ {
		head, err := l.Append(context.Background(), Event{Op: "put", Outcome: OutcomeOK})
		if err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
		if head == prev {
			t.Fatalf("event %d: head didn't advance", i)
		}
		prev = head
	}
}

func TestVerifyChain_DetectsClean(t *testing.T) {
	l, _, _ := freshLogger(t)
	for i := 0; i < 4; i++ {
		if _, err := l.Append(context.Background(), Event{Op: "get", Outcome: OutcomeOK}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	bad, total, _, err := l.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if bad != -1 {
		t.Fatalf("VerifyChain reported bad at %d on a clean log", bad)
	}
	if total != 4 {
		t.Fatalf("VerifyChain total = %d, want 4", total)
	}
}

func TestVerifyChain_DetectsTamperedLine(t *testing.T) {
	l, _, dir := freshLogger(t)
	for i := 0; i < 3; i++ {
		_, _ = l.Append(context.Background(), Event{Op: "put", Outcome: OutcomeOK, EntryName: "key" + string(rune('A'+i))})
	}
	// Read the log, mutate the middle line's outcome (preserves
	// hmac_chain field), write it back. Chain should fail at index 1.
	logPath, _ := filepath.Glob(filepath.Join(dir, "audit", "default", "*.log"))
	raw, _ := os.ReadFile(logPath[0])
	lines := splitLines(raw)
	var mid map[string]any
	if err := json.Unmarshal(lines[1], &mid); err != nil {
		t.Fatalf("unmarshal middle: %v", err)
	}
	mid["outcome"] = "tampered"
	bad, _ := json.Marshal(mid)
	mutated := append([]byte{}, lines[0]...)
	mutated = append(mutated, '\n')
	mutated = append(mutated, bad...)
	mutated = append(mutated, '\n')
	mutated = append(mutated, lines[2]...)
	mutated = append(mutated, '\n')
	if err := os.WriteFile(logPath[0], mutated, 0o600); err != nil {
		t.Fatalf("write back: %v", err)
	}

	badIdx, _, _, err := l.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if badIdx != 1 {
		t.Fatalf("VerifyChain bad idx = %d, want 1", badIdx)
	}
}

func TestNew_RejectsMissingSeed(t *testing.T) {
	store := &fakeStore{data: map[string]string{}}
	_, err := New(context.Background(), t.TempDir(), "vid", "default", store)
	if err == nil || !strings.Contains(err.Error(), "seed missing") {
		t.Fatalf("err = %v, want seed-missing", err)
	}
}

func TestNew_RejectsBadSeed(t *testing.T) {
	store := &fakeStore{data: map[string]string{MetaKeySeed: "not-hex"}}
	_, err := New(context.Background(), t.TempDir(), "vid", "default", store)
	if err == nil {
		t.Fatal("err = nil, want bad-seed")
	}
}

func TestAppend_Concurrent(t *testing.T) {
	l, _, _ := freshLogger(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = l.Append(context.Background(), Event{Op: "put", Outcome: OutcomeOK})
		}()
	}
	wg.Wait()
	bad, total, _, err := l.VerifyChain(context.Background())
	if err != nil || bad != -1 || total != 16 {
		t.Fatalf("concurrent append broke chain: bad=%d total=%d err=%v", bad, total, err)
	}
}

func TestStoreError_PropagatesFromHeadUpdate(t *testing.T) {
	var seed [32]byte
	_, _ = rand.Read(seed[:])
	store := &errStore{seed: seed[:]}
	dir := t.TempDir()
	l, err := New(context.Background(), dir, "vid", "default", store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = l.Append(context.Background(), Event{Op: "x"})
	if err == nil || !errors.Is(err, errStoreFail) {
		t.Fatalf("Append err = %v, want errStoreFail", err)
	}
}

// errStore is a fakeStore that fails MetaSet.
type errStore struct {
	seed []byte
}

var errStoreFail = errors.New("store: simulated failure")

func (e *errStore) MetaGet(_ context.Context, key string) (string, error) {
	if key == MetaKeySeed {
		return hex.EncodeToString(e.seed), nil
	}
	return "", nil
}

func (e *errStore) MetaSet(_ context.Context, _, _ string) error {
	return errStoreFail
}

func TestTail_EmptyLogReturnsNil(t *testing.T) {
	l, _, _ := freshLogger(t)
	events, err := l.Tail(context.Background(), 10, Filter{})
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if events != nil {
		t.Fatalf("Tail on empty log = %v, want nil", events)
	}
}

// TestTail_TolerateTrailingPartialLine simulates a writer that
// crashed mid-Append: the last line of the current month's file is
// half-written + missing its newline. Tail should return the
// well-formed prefix without erroring; only historical files (older
// than the current one) are required to be fully parsable.
func TestTail_TolerateTrailingPartialLine(t *testing.T) {
	l, _, dir := freshLogger(t)
	// Write 3 complete events.
	for i := 0; i < 3; i++ {
		if _, err := l.Append(context.Background(), Event{Op: "put", Outcome: OutcomeOK}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	// Identify and corrupt the trailing line of the latest log file.
	files, _ := filepath.Glob(filepath.Join(dir, "audit", "default", "*.log"))
	if len(files) == 0 {
		t.Fatalf("no log files written")
	}
	latest := files[len(files)-1]
	body, _ := os.ReadFile(latest)
	corrupted := make([]byte, 0, len(body)+32)
	corrupted = append(corrupted, body...)
	corrupted = append(corrupted, []byte(`{"op":"put","outcome":`)...) // truncated mid-key
	if err := os.WriteFile(latest, corrupted, 0o600); err != nil {
		t.Fatalf("rewrite log: %v", err)
	}
	// Tail must skip the partial trailer and still return the 3 good
	// events instead of erroring.
	got, err := l.Tail(context.Background(), 0, Filter{})
	if err != nil {
		t.Fatalf("Tail returned error on partial last line: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("Tail returned %d events, want 3 (partial trailer should be skipped)", len(got))
	}
}

func TestTail_AllAndLastN(t *testing.T) {
	l, _, _ := freshLogger(t)
	for i := 0; i < 7; i++ {
		if _, err := l.Append(context.Background(), Event{Op: "put", Outcome: OutcomeOK}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	// All when n <= 0 — the first event's Index is 0.
	all, err := l.Tail(context.Background(), 0, Filter{})
	if err != nil {
		t.Fatalf("Tail(0): %v", err)
	}
	if len(all) != 7 {
		t.Fatalf("Tail(0) returned %d events, want 7", len(all))
	}
	if all[0].Index != 0 {
		t.Errorf("Tail(0)[0].Index = %d, want 0", all[0].Index)
	}
	// Last 3 of 7 → global indices 4,5,6.
	last3, err := l.Tail(context.Background(), 3, Filter{})
	if err != nil {
		t.Fatalf("Tail(3): %v", err)
	}
	if len(last3) != 3 {
		t.Fatalf("Tail(3) returned %d events, want 3", len(last3))
	}
	if last3[0].Index != 4 {
		t.Errorf("Tail(3)[0].Index = %d, want 4 (last 3 of 7)", last3[0].Index)
	}
	// Order is preserved (oldest first), last3 should match all[-3:].
	for i := 0; i < 3; i++ {
		if last3[i].HMACChain != all[len(all)-3+i].HMACChain {
			t.Fatalf("Tail(3)[%d] HMAC mismatch", i)
		}
	}
}

// TestTail_Filter covers server-side filtering and that filtered (non-contiguous)
// results keep their TRUE global chain Index.
func TestTail_Filter(t *testing.T) {
	l, _, _ := freshLogger(t)
	ctx := context.Background()
	mk := func(proj, env, byn string, uid uint32) {
		if _, err := l.Append(ctx, Event{Op: "get", Outcome: OutcomeOK,
			Project: proj, Env: env, BynPath: byn, CallerUID: uid, CallerComm: "byn"}); err != nil {
			t.Fatal(err)
		}
	}
	mk("alpha", "prod", "/a/.byn", 501) // 0
	mk("beta", "dev", "/b/.byn", 502)   // 1
	mk("alpha", "dev", "/a/.byn", 501)  // 2
	mk("beta", "prod", "/c/.byn", 501)  // 3
	mk("alpha", "prod", "/a/.byn", 502) // 4

	got, err := l.Tail(ctx, 0, Filter{Scope: "alpha"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Index != 0 || got[1].Index != 2 || got[2].Index != 4 {
		t.Fatalf("scope alpha: want 3 events at indices 0,2,4, got %d events %v", len(got), idxOf(got))
	}
	if g, _ := l.Tail(ctx, 0, Filter{Byn: "/c/"}); len(g) != 1 || g[0].Index != 3 {
		t.Errorf("byn /c/: want 1 event @3, got %v", idxOf(g))
	}
	if g, _ := l.Tail(ctx, 0, Filter{Caller: "uid=502"}); len(g) != 2 {
		t.Errorf("caller uid=502: want 2, got %d", len(g))
	}
	if g, _ := l.Tail(ctx, 0, Filter{Scope: "alpha", Caller: "uid=502"}); len(g) != 1 || g[0].Index != 4 {
		t.Errorf("alpha AND uid=502: want 1 event @4, got %v", idxOf(g))
	}
	// Last-N applies AFTER the filter.
	if g, _ := l.Tail(ctx, 1, Filter{Scope: "alpha"}); len(g) != 1 || g[0].Index != 4 {
		t.Errorf("last 1 of alpha: want @4, got %v", idxOf(g))
	}
}

func idxOf(events []Event) []int {
	out := make([]int, len(events))
	for i, e := range events {
		out[i] = e.Index
	}
	return out
}
