package approval

import (
	"errors"
	"testing"
	"time"
)

func newStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	clock := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	s := Open(t.TempDir())
	s.SetClockForTesting(func() time.Time { return clock })
	return s, &clock
}

func req(subject, fingerprint string) Request {
	return Request{
		Kind:        KindTrustWidening,
		Subject:     subject,
		Fingerprint: fingerprint,
		Summary:     []string{"injects NEW_VAR"},
		Requestor:   Requestor{PID: 42, Exe: "/usr/bin/agent"},
	}
}

func TestEnqueueAndDecide(t *testing.T) {
	s, _ := newStore(t)
	got, err := s.Enqueue(req("/p/.byn", "fp1"))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if got.ID == "" || got.Status != StatusPending {
		t.Fatalf("bad request: %+v", got)
	}
	decided, err := s.Decide(got.ID, true, "terminal", "")
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decided.Status != StatusApproved || decided.DecidedVia != "terminal" {
		t.Fatalf("decision not recorded: %+v", decided)
	}
}

// An agent that retries in a loop must not turn into a wall of identical cards
// for the person deciding — that flood is how approval systems get beaten.
func TestEnqueue_CoalescesIdenticalQuestion(t *testing.T) {
	s, _ := newStore(t)
	first, err := s.Enqueue(req("/p/.byn", "fp1"))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	for i := 0; i < 25; i++ {
		again, err := s.Enqueue(req("/p/.byn", "fp1"))
		if err != nil {
			t.Fatalf("re-enqueue %d: %v", i, err)
		}
		if again.ID != first.ID {
			t.Fatalf("identical question got a second id: %s vs %s", again.ID, first.ID)
		}
	}
	pending, err := s.List(StatusPending)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("got %d pending cards, want 1", len(pending))
	}
	if pending[0].Repeats == 0 {
		t.Error("repeat count not recorded")
	}
}

// Distinct questions from one project are still bounded, so a caller cannot
// manufacture unlimited cards by varying what it asks for.
func TestEnqueue_RateLimitsPerProject(t *testing.T) {
	s, _ := newStore(t)
	for i := 0; i < MaxPendingPerProject; i++ {
		if _, err := s.Enqueue(req("/p/.byn", string(rune('a'+i)))); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if _, err := s.Enqueue(req("/p/.byn", "one-too-many")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	// A different project is unaffected.
	if _, err := s.Enqueue(req("/other/.byn", "fp1")); err != nil {
		t.Fatalf("unrelated project was rate limited: %v", err)
	}
}

// Refusing should cost the asker something; otherwise the same question can be
// re-asked until someone taps yes out of fatigue.
func TestDecide_RepeatedDenialPutsQuestionOnHold(t *testing.T) {
	s, _ := newStore(t)
	for i := 0; i < MaxDenialsBeforeHold; i++ {
		r, err := s.Enqueue(req("/p/.byn", "fp-nope"))
		if err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
		if _, err := s.Decide(r.ID, false, "terminal", ""); err != nil {
			t.Fatalf("deny %d: %v", i, err)
		}
	}
	_, err := s.Enqueue(req("/p/.byn", "fp-nope"))
	if !errors.Is(err, ErrOnHold) {
		t.Fatalf("err = %v, want ErrOnHold", err)
	}
	// A different question is unaffected by the hold.
	if _, err := s.Enqueue(req("/p/.byn", "fp-other")); err != nil {
		t.Fatalf("unrelated question blocked by hold: %v", err)
	}
}

func TestDecide_HoldLiftsAfterCooldown(t *testing.T) {
	s, clock := newStore(t)
	for i := 0; i < MaxDenialsBeforeHold; i++ {
		r, _ := s.Enqueue(req("/p/.byn", "fp-nope"))
		if _, err := s.Decide(r.ID, false, "terminal", ""); err != nil {
			t.Fatalf("deny: %v", err)
		}
	}
	*clock = clock.Add(DenialHoldFor + time.Minute)
	if _, err := s.Enqueue(req("/p/.byn", "fp-nope")); err != nil {
		t.Fatalf("hold did not lift: %v", err)
	}
}

// A decision can arrive twice — two surfaces racing, or a late notification —
// and the second must not be an error the caller has to interpret.
func TestDecide_IsIdempotent(t *testing.T) {
	s, _ := newStore(t)
	r, _ := s.Enqueue(req("/p/.byn", "fp1"))
	first, err := s.Decide(r.ID, true, "phone", "")
	if err != nil {
		t.Fatalf("first decide: %v", err)
	}
	second, err := s.Decide(r.ID, false, "terminal", "")
	if err != nil {
		t.Fatalf("repeat decide errored: %v", err)
	}
	if second.Status != first.Status || second.DecidedVia != "phone" {
		t.Fatalf("a later decision overwrote the first: %+v", second)
	}
}

// "Nobody answered in time" must be distinguishable from "answered no", so a
// caller can retry rather than treat expiry as refusal.
func TestExpiry_IsItsOwnState(t *testing.T) {
	s, clock := newStore(t)
	r, _ := s.Enqueue(req("/p/.byn", "fp1"))
	*clock = clock.Add(DefaultTTL + time.Minute)

	got, err := s.Get(r.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != StatusExpired {
		t.Fatalf("status = %s, want expired", got.Status)
	}
	if got.Answered() {
		t.Error("an expired request must not read as answered")
	}
	// The question can be asked again once it has lapsed.
	again, err := s.Enqueue(req("/p/.byn", "fp1"))
	if err != nil {
		t.Fatalf("re-ask after expiry: %v", err)
	}
	if again.ID == r.ID {
		t.Error("re-asking after expiry reused the lapsed card")
	}
}

// The TTL has to outlast a late notification; a short window expires requests
// through no fault of the person answering them.
func TestDefaultTTL_OutlastsSlowNotifications(t *testing.T) {
	if DefaultTTL < time.Hour {
		t.Fatalf("DefaultTTL = %s; too short to survive a delayed push", DefaultTTL)
	}
}

// Pruning must never remove a question nobody has answered — an unanswered
// request vanishing on its own is the failure this queue exists to prevent.
func TestPrune_KeepsPendingForever(t *testing.T) {
	s, clock := newStore(t)
	longLived := req("/p/.byn", "fp-pending")
	longLived.ExpiresAt = clock.Add(365 * 24 * time.Hour)
	pending, _ := s.Enqueue(longLived)
	answered, _ := s.Enqueue(req("/p/.byn", "fp-answered"))
	if _, err := s.Decide(answered.ID, true, "terminal", ""); err != nil {
		t.Fatalf("decide: %v", err)
	}

	*clock = clock.Add(30 * 24 * time.Hour)
	dropped, err := s.Prune(7 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped %d, want 1 (the answered one)", dropped)
	}
	if _, err := s.Get(pending.ID); err != nil {
		t.Fatalf("pending request was pruned: %v", err)
	}
}

func TestGet_UnknownID(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// The queue must survive a daemon restart: decisions and pending questions are
// on disk, not in memory.
func TestStore_PersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s1 := Open(dir)
	r, err := s1.Enqueue(req("/p/.byn", "fp1"))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	s2 := Open(dir)
	got, err := s2.Get(r.ID)
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if got.Status != StatusPending || got.Subject != "/p/.byn" {
		t.Fatalf("request did not survive reopen: %+v", got)
	}
}
