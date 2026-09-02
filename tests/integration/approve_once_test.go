//go:build integration

package integration

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestE2E_ExecAskOnce_PlainApprovalGrantsASingleUse drives the whole path a
// real agent takes: ask with --once, approve without flags, and check that a
// single-use grant came out.
//
// It is an integration test on purpose. The rule lives in the daemon so every
// surface answers alike, which means a unit test of the CLI proves nothing
// about what `byn approve <id>` actually does — the two halves are in different
// processes, and byn has been bitten before by a feature that was correct in
// both halves and never connected.
func TestE2E_ExecAskOnce_PlainApprovalGrantsASingleUse(t *testing.T) {
	bynContent := "[scope]\nproject = \"alpha\"\n[exec]\nenv = []\n"
	s, projDir, dotPath := bootstrapExecFetch(t, bynContent)

	if _, se, code := s.runInDir(projDir, execfetchPW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}

	// The agent says it needs this once.
	if _, _, code := s.runInDir(projDir, "", nil, "exec", "--once", "--", "/usr/bin/env"); code == 0 {
		t.Fatal("unpinned exec should not run without approval")
	}

	id, entry := singlePendingApproval(t, s)
	if !entry.AskOnce {
		t.Fatalf("the request did not carry the asker's --once: %+v", entry)
	}

	// A plain approval — no --once — must honour what was asked for.
	if _, se, code := s.run(execfetchPW+"\n", "approve", "--password-stdin", id); code != 0 {
		t.Fatalf("approve: code=%d stderr=%q", code, se)
	}

	_, granted := approvalByID(t, s, id)
	if !granted.Once {
		t.Fatal("a plain approval of a --once request must grant a single use")
	}
	if granted.GrantedUntil == 0 {
		t.Fatal("a single-use grant still needs a window; an unspent grant must lapse")
	}
}

// The approver's override is the other half of the contract: an owner who wants
// to grant normally can, even when the asker asked for less.
func TestE2E_ApproveAlways_OverridesTheAskersOnce(t *testing.T) {
	bynContent := "[scope]\nproject = \"alpha\"\n[exec]\nenv = []\n"
	s, projDir, dotPath := bootstrapExecFetch(t, bynContent)

	if _, se, code := s.runInDir(projDir, execfetchPW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}
	if _, _, code := s.runInDir(projDir, "", nil, "exec", "--once", "--", "/usr/bin/env"); code == 0 {
		t.Fatal("unpinned exec should not run without approval")
	}

	id, _ := singlePendingApproval(t, s)
	if _, se, code := s.run(execfetchPW+"\n", "approve", "--password-stdin", "--always", id); code != 0 {
		t.Fatalf("approve --always: code=%d stderr=%q", code, se)
	}
	_, granted := approvalByID(t, s, id)
	if granted.Once {
		t.Fatal("--always must override the asker's single-use request")
	}
}

// approvalEntryJSON is the subset of `byn approve --json` this test reads.
type approvalEntryJSON struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Once         bool   `json:"once"`
	AskOnce      bool   `json:"ask_once"`
	GrantedUntil int64  `json:"granted_until"`
}

func listApprovalsJSON(t *testing.T, s *session, args ...string) []approvalEntryJSON {
	t.Helper()
	stdout, stderr, code := s.run("", append([]string{"approve", "--json"}, args...)...)
	if code != 0 {
		t.Fatalf("approve --json: code=%d stderr=%q", code, stderr)
	}
	var entries []approvalEntryJSON
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &entries); err != nil {
		t.Fatalf("approve --json is not a JSON array: %v\n%s", err, stdout)
	}
	return entries
}

func singlePendingApproval(t *testing.T, s *session) (string, approvalEntryJSON) {
	t.Helper()
	entries := listApprovalsJSON(t, s)
	if len(entries) != 1 {
		t.Fatalf("want exactly one pending request, got %d", len(entries))
	}
	return entries[0].ID, entries[0]
}

func approvalByID(t *testing.T, s *session, id string) (string, approvalEntryJSON) {
	t.Helper()
	for _, e := range listApprovalsJSON(t, s, "--history") {
		if e.ID == id {
			return e.ID, e
		}
	}
	t.Fatalf("request %s not found in history", id)
	return "", approvalEntryJSON{}
}
