//go:build integration

package integration

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// bootstrapWatch trusts a .byn with no pinned actions, so any exec raises an
// approval — the situation an agent actually meets.
func bootstrapWatch(t *testing.T) (*session, string, string) {
	t.Helper()
	s, projDir, dotPath := bootstrapExecFetch(t, "[scope]\nproject = \"alpha\"\n[exec]\nenv = []\n")
	if _, se, code := s.runInDir(projDir, execfetchPW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}
	return s, projDir, dotPath
}

// raiseAndTakeTicket runs an exec that must be approved, and returns the watch
// ticket byn handed back with the refusal.
func raiseAndTakeTicket(t *testing.T, s *session, projDir string) (id, ticket string) {
	t.Helper()
	stdout, _, _ := s.runInDir(projDir, "", nil, "exec", "--json", "--", "/usr/bin/env")
	var payload struct {
		ApprovalID  string `json:"approval_id"`
		WatchTicket string `json:"watch_ticket"`
	}
	if err := json.Unmarshal([]byte(firstJSONLine(stdout)), &payload); err != nil {
		t.Fatalf("exec --json is not parseable: %v\n%s", err, stdout)
	}
	if payload.ApprovalID == "" || payload.WatchTicket == "" {
		t.Fatalf("refusal must carry both an id and a watch ticket, got %+v\n%s", payload, stdout)
	}
	return payload.ApprovalID, payload.WatchTicket
}

func firstJSONLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "{") {
			return ln
		}
	}
	return s
}

// TestE2E_Watch_LearnsTheDecisionAndTheReason is the feature in one test: an
// agent is told the outcome of its own request, and told WHY, without polling.
func TestE2E_Watch_LearnsTheDecisionAndTheReason(t *testing.T) {
	s, projDir, _ := bootstrapWatch(t)
	id, ticket := raiseAndTakeTicket(t, s, projDir)

	type result struct{ out string }
	done := make(chan result, 1)
	go func() {
		stdout, _, _ := s.run("", "request", "watch", "--timeout", "30", ticket)
		done <- result{stdout}
	}()

	// Let the watch land before deciding, so this exercises the notify path
	// rather than the already-answered shortcut.
	time.Sleep(750 * time.Millisecond)
	if _, se, code := s.run(execfetchPW+"\n", "approve", "--password-stdin",
		"--reason", "needed for the release", id); code != 0 {
		t.Fatalf("approve: code=%d stderr=%q", code, se)
	}

	var got result
	select {
	case got = <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("watch never returned after the request was decided")
	}
	var resp struct {
		ApprovalID   string `json:"approval_id"`
		Status       string `json:"status"`
		Reason       string `json:"reason"`
		GrantedUntil int64  `json:"granted_until"`
		TimedOut     bool   `json:"timed_out"`
	}
	if err := json.Unmarshal([]byte(firstJSONLine(got.out)), &resp); err != nil {
		t.Fatalf("watch output is not JSON: %v\n%s", err, got.out)
	}
	if resp.Status != "approved" || resp.TimedOut {
		t.Fatalf("want an approved decision, got %+v", resp)
	}
	if resp.ApprovalID != id {
		t.Fatalf("watch reported %s, want %s", resp.ApprovalID, id)
	}
	// The reason is the half that exists nowhere else for the asker.
	if resp.Reason != "needed for the release" {
		t.Fatalf("the decider's reason must reach the asker, got %q", resp.Reason)
	}
}

// A denial must be distinguishable from silence, or an agent retries a refusal
// for ever.
func TestE2E_Watch_ReportsADenialWithItsReason(t *testing.T) {
	s, projDir, _ := bootstrapWatch(t)
	id, ticket := raiseAndTakeTicket(t, s, projDir)

	if _, se, code := s.run("", "approve", "--deny", "--reason", "wrong target", id); code != 0 {
		t.Fatalf("deny: code=%d stderr=%q", code, se)
	}
	stdout, _, code := s.run("", "request", "watch", "--timeout", "10", ticket)
	var resp struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(firstJSONLine(stdout)), &resp); err != nil {
		t.Fatalf("watch output is not JSON: %v\n%s", err, stdout)
	}
	if resp.Status != "denied" || resp.Reason != "wrong target" {
		t.Fatalf("want denied with its reason, got %+v", resp)
	}
	if code == 0 {
		t.Fatal("a denial must not exit 0 — a script branching on the code would treat it as granted")
	}
}

// The anti-hijack property, stated as a test: a second caller asking the same
// question joins the existing card and is handed no ticket.
func TestE2E_Watch_TicketIsIssuedOnlyToTheCallerThatRaisedIt(t *testing.T) {
	s, projDir, _ := bootstrapWatch(t)
	firstID, firstTicket := raiseAndTakeTicket(t, s, projDir)

	stdout, _, _ := s.runInDir(projDir, "", nil, "exec", "--json", "--", "/usr/bin/env")
	var second struct {
		ApprovalID  string `json:"approval_id"`
		WatchTicket string `json:"watch_ticket"`
	}
	if err := json.Unmarshal([]byte(firstJSONLine(stdout)), &second); err != nil {
		t.Fatalf("exec --json is not parseable: %v\n%s", err, stdout)
	}
	if second.ApprovalID != firstID {
		t.Fatalf("the same question must coalesce onto one card: got %s, want %s", second.ApprovalID, firstID)
	}
	if second.WatchTicket != "" {
		t.Fatal("a re-attached request must NOT be handed a ticket — that is how one agent " +
			"would acquire another's channel by asking for the same thing")
	}
	if firstTicket == "" {
		t.Fatal("the caller that raised it must have got one")
	}
}

// An agent that no longer needs a command takes the question off the owner's
// list — and cancelling must not read as a refusal.
func TestE2E_Cancel_WithdrawsWithoutCountingAsADenial(t *testing.T) {
	s, projDir, _ := bootstrapWatch(t)
	id, ticket := raiseAndTakeTicket(t, s, projDir)

	if _, se, code := s.run("", "request", "cancel", ticket); code != 0 {
		t.Fatalf("cancel: code=%d stderr=%q", code, se)
	}
	stdout, _, _ := s.run("", "approve", "--history", "--json")
	var entries []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &entries); err != nil {
		t.Fatalf("history --json unparseable: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.ID == id {
			found = true
			if e.Status != "cancelled" {
				t.Fatalf("want status cancelled, got %q", e.Status)
			}
		}
	}
	if !found {
		t.Fatalf("the withdrawn request must still be on record, not vanish")
	}
	// Nothing is left waiting for the owner.
	pending, _, _ := s.run("", "approve", "--json")
	var open []struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(strings.TrimSpace(pending)), &open)
	for _, e := range open {
		if e.ID == id {
			t.Fatal("a cancelled request must leave the pending list")
		}
	}
}

// An unknown ticket must not reveal whether it was wrong or merely finished.
func TestE2E_Watch_UnknownTicketIsRefusedWithoutAnOracle(t *testing.T) {
	s, _, _ := bootstrapWatch(t)
	_, stderr, code := s.run("", "request", "watch", "--timeout", "5", "not-a-real-ticket")
	if code == 0 {
		t.Fatal("an unknown ticket must not succeed")
	}
	if strings.Contains(strings.ToLower(stderr), "expired") {
		t.Fatalf("the refusal must not say WHY it did not match — that is a probe oracle: %q", stderr)
	}
}
