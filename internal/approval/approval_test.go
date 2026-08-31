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
	// The same answer again changes nothing and says nothing: two surfaces
	// agreeing is not a conflict.
	same, err := s.Decide(r.ID, true, "terminal", "")
	if err != nil {
		t.Fatalf("repeating the same decision errored: %v", err)
	}
	if same.Status != first.Status || same.DecidedVia != "phone" {
		t.Fatalf("a later decision overwrote the first: %+v", same)
	}
}

// Denying something already approved must not look like it worked.
//
// It returned the existing record with no error, and the line it printed even
// said "approved … runs free for 5h53m" — so an owner who typed it to take a
// grant back believed they had, and were wrong about what was still runnable.
// The first decision still stands; what changes is that byn says so.
func TestDecide_DenyingAnApprovalIsRefusedNotIgnored(t *testing.T) {
	s, _ := newStore(t)
	r, _ := s.Enqueue(req("/p/.byn", "fp-deny-after-approve"))
	if _, err := s.Decide(r.ID, true, "terminal", ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	got, err := s.Decide(r.ID, false, "terminal", "")
	if err == nil {
		t.Fatal("denying an approved request reported success")
	}
	if !errors.Is(err, ErrAlreadyDecided) {
		t.Errorf("err = %v, want ErrAlreadyDecided", err)
	}
	if got.Status != StatusApproved {
		t.Errorf("status = %s, want the first decision to stand", got.Status)
	}
}

// A grant has to be removable while it still has time to run: the one-shot
// script is the shape approvals get used for, and "it expires in six hours" is
// not an answer to "this must stop being runnable now".
func TestRevoke_TakesTheGrantBack(t *testing.T) {
	s, clock := newStore(t)
	r := req("/p/.byn", "fp-revoke")
	r.Kind = KindActionUnpinned
	pending, err := s.Enqueue(r)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := s.Decide(pending.ID, true, "terminal", ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	granted, until, err := s.ActionGrantedUntil("/p/.byn", "fp-revoke")
	if err != nil || !granted {
		t.Fatalf("expected a live grant: granted=%v err=%v", granted, err)
	}
	if !until.After(*clock) {
		t.Fatal("grant should outlive now")
	}

	revoked, err := s.Revoke(pending.ID)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.Status != StatusRevoked {
		t.Errorf("status = %s, want revoked", revoked.Status)
	}
	// The grant is what authorises a command, so it must actually be gone —
	// relabelling the record while leaving it runnable would be the worst of
	// both, an owner told it was revoked and a command that still runs.
	granted, _, err = s.ActionGrantedUntil("/p/.byn", "fp-revoke")
	if err != nil {
		t.Fatalf("lookup after revoke: %v", err)
	}
	if granted {
		t.Error("the command still runs free after its grant was revoked")
	}
}

// Revoking something that was never granted is an error, not a quiet success:
// the owner is asking to remove a capability, and needs to know if there was
// none to remove.
func TestRevoke_RefusesWhatWasNeverApproved(t *testing.T) {
	s, _ := newStore(t)
	pending, err := s.Enqueue(req("/p/.byn", "fp-open"))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := s.Revoke(pending.ID); !errors.Is(err, ErrNotApproved) {
		t.Errorf("err = %v, want ErrNotApproved", err)
	}
	if _, err := s.Revoke("nosuchid"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
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

// The wall must reflect the LAST decision, not whichever one the scan met first.
//
// The first version decided inside the loop and returned as soon as it saw an
// approval, so an older approval ordered before a newer refusal reported "not
// refused" — turning the wall off for precisely the command someone had just
// said no to. A live run hit it: a command approved in the morning and denied in
// the afternoon raised a fresh request instead of stopping.
func TestLastDenial_TakesTheMostRecentDecision(t *testing.T) {
	dir := t.TempDir()
	s := Open(dir)
	now := time.Now()
	s.SetClockForTesting(func() time.Time { return now })

	raise := func() Request {
		t.Helper()
		r, err := s.Enqueue(Request{
			Kind: KindActionUnpinned, Subject: "/p/.byn",
			Fingerprint: "fp-1", Summary: []string{"runs cleanup"},
		})
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		return r
	}

	// Approved first, then denied later: the refusal is the last word.
	first := raise()
	if _, err := s.Decide(first.ID, true, "terminal", ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	now = now.Add(time.Hour)
	second := raise()
	if _, err := s.Decide(second.ID, false, "terminal", "wrong target"); err != nil {
		t.Fatalf("deny: %v", err)
	}
	got, refused := s.LastDenial("/p/.byn", "fp-1")
	if !refused {
		t.Fatal("an approval followed by a refusal must leave the command refused")
	}
	if got.DecidedReason != "wrong target" {
		t.Errorf("reason = %q, want the most recent decision's", got.DecidedReason)
	}

	// And the other way round: a later approval clears the wall.
	now = now.Add(time.Hour)
	third := raise()
	if _, err := s.Decide(third.ID, true, "terminal", ""); err != nil {
		t.Fatalf("approve again: %v", err)
	}
	if _, refused := s.LastDenial("/p/.byn", "fp-1"); refused {
		t.Error("a refusal followed by an approval must clear the wall")
	}
}

// A retry that explains itself should improve a card that did not, without
// letting a later retry rewrite a reason someone may already be reading.
func TestEnqueue_ReasonFilledOnceNeverRewritten(t *testing.T) {
	s, _ := newStore(t)

	first, err := s.Enqueue(Request{
		Kind: KindActionUnpinned, Subject: "/p/.byn",
		Fingerprint: "fp", Summary: []string{"runs make dev"},
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if first.Reason != "" {
		t.Fatalf("reason = %q, want empty", first.Reason)
	}

	// Same question, now explained: the blank gets filled.
	second, err := s.Enqueue(Request{
		Kind: KindActionUnpinned, Subject: "/p/.byn",
		Fingerprint: "fp", Summary: []string{"runs make dev"},
		Reason: "starting the api for the auth work",
	})
	if err != nil {
		t.Fatalf("enqueue retry: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("retry made a second card (%s vs %s)", second.ID, first.ID)
	}
	if second.Reason != "starting the api for the auth work" {
		t.Errorf("reason = %q, want the retry's", second.Reason)
	}

	// A third asking must not overwrite it: the stated purpose cannot drift
	// while the person deciding is reading it.
	third, err := s.Enqueue(Request{
		Kind: KindActionUnpinned, Subject: "/p/.byn",
		Fingerprint: "fp", Summary: []string{"runs make dev"},
		Reason: "something else entirely",
	})
	if err != nil {
		t.Fatalf("enqueue third: %v", err)
	}
	if third.Reason != "starting the api for the auth work" {
		t.Errorf("reason = %q, want the first one given", third.Reason)
	}
	if third.Repeats != 2 {
		t.Errorf("repeats = %d, want 2", third.Repeats)
	}
}

func TestRequestor_StringNamesTheAgentNotTheProcess(t *testing.T) {
	got := Requestor{PID: 91, Exe: "byn", Agent: "claude", AgentPID: 42}.String()
	if got != "claude (pid 42), no terminal" {
		t.Errorf("String() = %q", got)
	}
	if got := (Requestor{PID: 91}).String(); got != "pid 91" {
		t.Errorf("with no agent: String() = %q, want \"pid 91\"", got)
	}
	if got := (Requestor{}).String(); got != "" {
		t.Errorf("with nothing known: String() = %q, want empty", got)
	}
}

// An answer that lands after the asker gave up still grants — it just grants to
// nobody who is listening. Saying so is the difference between a grant someone
// can account for and one that appears from nowhere.
func TestDecide_LateAnswerGrantsAndSaysSo(t *testing.T) {
	s, clock := newStore(t)

	r := req("/p/.byn", "fp-late")
	r.Kind = KindActionUnpinned
	r.NeededBy = clock.Add(2 * time.Minute)
	pending, err := s.Enqueue(r)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	*clock = clock.Add(10 * time.Minute) // the asker has long since exited 75
	decided, err := s.Decide(pending.ID, true, "terminal", "")
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decided.Status != StatusApproved {
		t.Fatalf("status = %s, want approved — a late answer is still an answer", decided.Status)
	}
	if !decided.Late {
		t.Error("a decision after NeededBy is not marked late")
	}
	if decided.GrantedUntil.IsZero() {
		t.Error("late or not, the command should have been granted")
	}

	// In time, and it is not late.
	s2, clock2 := newStore(t)
	r2 := req("/p/.byn", "fp-ontime")
	r2.Kind = KindActionUnpinned
	r2.NeededBy = clock2.Add(2 * time.Minute)
	p2, err := s2.Enqueue(r2)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	*clock2 = clock2.Add(30 * time.Second)
	d2, err := s2.Decide(p2.ID, true, "terminal", "")
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if d2.Late {
		t.Error("an answer inside the window was marked late")
	}
}

// A request with no stated deadline is never late: a caller that never said it
// was waiting cannot have stopped.
func TestDecide_NoDeadlineIsNeverLate(t *testing.T) {
	s, clock := newStore(t)
	pending, err := s.Enqueue(req("/p/.byn", "fp-none"))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	*clock = clock.Add(5 * time.Hour)
	decided, err := s.Decide(pending.ID, true, "terminal", "")
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decided.Late {
		t.Error("a request that stated no deadline was marked late")
	}
}

// The owner can shorten the window a command runs free. Six hours for something
// wanted once is a standing authority nobody asked for.
func TestDecideFor_OwnerSetsTheGrantWindow(t *testing.T) {
	s, clock := newStore(t)
	r := req("/p/.byn", "fp-window")
	r.Kind = KindActionUnpinned
	pending, err := s.Enqueue(r)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	decided, err := s.DecideFor(pending.ID, true, "terminal", "", 20*time.Minute)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if got := decided.GrantedUntil.Sub(*clock); got != 20*time.Minute {
		t.Errorf("granted for %s, want 20m", got)
	}

	// Zero still means the default, so nothing changes for callers that do not
	// choose a window.
	s2, clock2 := newStore(t)
	r2 := req("/p/.byn", "fp-default")
	r2.Kind = KindActionUnpinned
	p2, err := s2.Enqueue(r2)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	d2, err := s2.DecideFor(p2.ID, true, "terminal", "", 0)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if got := d2.GrantedUntil.Sub(*clock2); got != ActionGrantFor {
		t.Errorf("granted for %s, want the default %s", got, ActionGrantFor)
	}
}
