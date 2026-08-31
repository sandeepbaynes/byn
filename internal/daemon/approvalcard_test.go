//go:build byntest

package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// A card has to answer two questions before anyone can decide from it: who
// asked, and what for. The first is byn's to establish and the second is the
// asker's to claim — and the card must never confuse the two.
func TestApprovalCard_SaysWhoAskedAndWhyTheySaidTheyDid(t *testing.T) {
	_ = stubOrigin(t, true)
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nactions = [\"pinned run\"]\n")
	grantBynFile(t, c, byn, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "make dev", Argv: []string{"make", "dev"},
		Reason: "starting the api so I can test the auth change",
	})
	if code := errCode(t, err); code != ipc.CodeApprovalPending {
		t.Fatalf("code = %v, want approval_pending", code)
	}

	var list ipc.ApprovalListResp
	if cerr := c.Call(ipc.OpApprovalList, ipc.ApprovalListReq{Status: "pending"}, &list); cerr != nil {
		t.Fatalf("list: %v", cerr)
	}
	if len(list.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(list.Entries))
	}
	e := list.Entries[0]

	if e.Reason != "starting the api so I can test the auth change" {
		t.Errorf("reason = %q", e.Reason)
	}
	// The requestor is read from the kernel, so the one thing it must never be
	// is the command being asked about — which is what it used to hold, making
	// the "who" line a second copy of the "what" line.
	if e.Requestor.Exe == "make dev" || e.Requestor.Exe == e.Summary[0] {
		t.Errorf("requestor.exe = %q — that is the request, not the asker", e.Requestor.Exe)
	}
	if e.Requestor.PID == 0 {
		t.Error("requestor has no pid")
	}
	if e.Requestor.Display == "" {
		t.Error("requestor has no one-line form for a surface to show")
	}
}

// The reason is written by whatever called byn and printed on a person's
// terminal, so it is untrusted input on its way to a screen. Escape sequences
// in it must not survive to repaint the decision someone is about to make.
func TestApprovalCard_ReasonCannotRepaintTheTerminal(t *testing.T) {
	hostile := "\x1b[2Jwipe\x1b[31m the screen\nand forge\ta second line\r"
	got := requestReason(hostile)
	if strings.ContainsAny(got, "\x1b\n\r") {
		t.Fatalf("control characters survived: %q", got)
	}
	if got != "[2Jwipe[31m the screen and forge a second line" {
		t.Errorf("reason = %q", got)
	}
	if len(requestReason(strings.Repeat("x", 500))) > 210 {
		t.Error("an unbounded reason can push everything else off the card")
	}
}

// A caller that is waiting says so, and the card can then tell an urgent
// request from an abandoned one. A caller that is not waiting states no
// deadline: claiming one would put a hurry on the list with nothing behind it.
func TestApprovalCard_DeadlineComesFromTheCaller(t *testing.T) {
	_ = stubOrigin(t, true)
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nactions = [\"pinned run\"]\n")
	grantBynFile(t, c, byn, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "make dev", Argv: []string{"make", "dev"},
		WaitSeconds: 120,
	})
	if code := errCode(t, err); code != ipc.CodeApprovalPending {
		t.Fatalf("code = %v, want approval_pending", code)
	}
	waiting := onlyPending(t, c)
	if waiting.NeededBy == 0 {
		t.Fatal("a waiting caller's request carries no deadline")
	}
	if left := time.Until(time.Unix(waiting.NeededBy, 0)); left <= 0 || left > 3*time.Minute {
		t.Errorf("needed_by is %s away, want about 2m", left)
	}

	// A different command, from a caller that is not waiting.
	_, err = execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "make test", Argv: []string{"make", "test"},
	})
	if code := errCode(t, err); code != ipc.CodeApprovalPending {
		t.Fatalf("code = %v, want approval_pending", code)
	}
	for _, e := range allPending(t, c) {
		if e.ID == waiting.ID {
			continue
		}
		if e.NeededBy != 0 {
			t.Errorf("a non-waiting caller was given a deadline: %d", e.NeededBy)
		}
	}
}

// An owner may cap how long an approved command runs free, and an absurd window
// is refused rather than honoured — it decides how long something runs without
// being asked again.
func TestApprovalCard_OwnerCanShortenTheGrant(t *testing.T) {
	_ = stubOrigin(t, true)
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nactions = [\"pinned run\"]\n")
	grantBynFile(t, c, byn, pw)
	if _, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "make dev", Argv: []string{"make", "dev"},
	}); errCode(t, err) != ipc.CodeApprovalPending {
		t.Fatalf("wanted a queued request")
	}
	pending := onlyPending(t, c)

	if err := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
		ID: pending.ID, Approve: true, Password: pw,
		GrantForSeconds: int((48 * time.Hour) / time.Second),
	}, &ipc.ApprovalDecideResp{}); err == nil {
		t.Fatal("a 48h grant window was accepted")
	}

	var resp ipc.ApprovalDecideResp
	if err := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
		ID: pending.ID, Approve: true, Password: pw,
		GrantForSeconds: int((20 * time.Minute) / time.Second),
	}, &resp); err != nil {
		t.Fatalf("decide: %v", err)
	}
	left := time.Until(time.Unix(resp.Entry.GrantedUntil, 0))
	if left <= 0 || left > 25*time.Minute {
		t.Errorf("granted for %s, want about 20m", left)
	}
}

func allPending(t *testing.T, c *ipc.Client) []ipc.ApprovalEntry {
	t.Helper()
	var list ipc.ApprovalListResp
	if err := c.Call(ipc.OpApprovalList, ipc.ApprovalListReq{Status: "pending"}, &list); err != nil {
		t.Fatalf("list: %v", err)
	}
	return list.Entries
}

func onlyPending(t *testing.T, c *ipc.Client) ipc.ApprovalEntry {
	t.Helper()
	got := allPending(t, c)
	if len(got) != 1 {
		t.Fatalf("pending = %d, want 1", len(got))
	}
	return got[0]
}

// A grant answers a question about one asker. Letting anything in the project
// use it afterwards is a wider authority than the owner was asked for, so the
// binding is the default and widening is deliberate.
func TestGrant_BoundToWhoeverAsked(t *testing.T) {
	origin := stubOrigin(t, true)
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nactions = [\"pinned run\"]\n")
	grantBynFile(t, c, byn, pw)
	run := func() error {
		_, err := execFetch(t, c, ipc.ExecFetchReq{
			Path: byn, Command: "make dev", Argv: []string{"make", "dev"},
		})
		return err
	}
	if code := errCode(t, run()); code != ipc.CodeApprovalPending {
		t.Fatalf("code = %v, want approval_pending", code)
	}
	pending := onlyPending(t, c)
	if _, err := decideApproval(t, c, ipc.ApprovalDecideReq{
		ID: pending.ID, Approve: true, Password: pw,
	}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// The asker runs free.
	if err := run(); err != nil {
		t.Fatalf("the caller that asked was refused its own grant: %v", err)
	}

	// Somebody else in the same project, running the same command, is not
	// covered by it — that is the whole point of binding.
	origin(false) // a different caller from here on
	if code := errCode(t, run()); code != ipc.CodeApprovalPending {
		t.Fatalf("another caller inherited a grant answered for someone else: code = %v", code)
	}
}

// The owner can widen a grant deliberately: a shared build command, or one that
// has to outlive the session that asked.
func TestGrant_AnyoneWidensItOnPurpose(t *testing.T) {
	origin := stubOrigin(t, true)
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nactions = [\"pinned run\"]\n")
	grantBynFile(t, c, byn, pw)
	run := func() error {
		_, err := execFetch(t, c, ipc.ExecFetchReq{
			Path: byn, Command: "make dev", Argv: []string{"make", "dev"},
		})
		return err
	}
	if code := errCode(t, run()); code != ipc.CodeApprovalPending {
		t.Fatalf("code = %v, want approval_pending", code)
	}
	pending := onlyPending(t, c)
	resp, err := decideApproval(t, c, ipc.ApprovalDecideReq{
		ID: pending.ID, Approve: true, Password: pw, Anyone: true,
	})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !resp.Entry.Anyone {
		t.Error("the widening was not recorded, so no surface can show it")
	}

	origin(false) // a different caller from here on
	if err := run(); err != nil {
		t.Fatalf("--anyone did not widen the grant: %v", err)
	}
}

func decideApproval(t *testing.T, c *ipc.Client, req ipc.ApprovalDecideReq) (ipc.ApprovalDecideResp, error) {
	t.Helper()
	var resp ipc.ApprovalDecideResp
	err := c.Call(ipc.OpApprovalDecide, req, &resp)
	return resp, err
}

// The audit question must have an answer that is not "print every secret".
//
// This is here because of what happened without it: the only command that could
// say whether a value had been rotated was the one that prints them all, so
// answering an audit question put a live credential into a chat window. Verify
// needs no credential and works locked, because comparing digests of stored
// ciphertext needs no key.
func TestRunDiff_AnswersWithNoCredentialAndNoValues(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"KEPT\", \"ROTATED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "KEPT", []byte("kept-v1"))
	putVar(t, c, ipc.Scope{}, "ROTATED", []byte("rotated-v1"))
	grantBynFile(t, c, byn, pw)
	if _, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"},
	}); err != nil {
		t.Fatalf("exec: %v", err)
	}
	var list ipc.RunListResp
	if err := c.Call(ipc.OpRunList, ipc.RunListReq{Limit: 5}, &list); err != nil {
		t.Fatalf("list: %v", err)
	}
	id := list.Entries[0].ID

	putVar(t, c, ipc.Scope{}, "ROTATED", []byte("rotated-v2"))

	lockVaultStore(t, d, "default")
	c.Session = nil

	var got ipc.RunListResp
	if err := c.Call(ipc.OpRunList, ipc.RunListReq{ID: id, Diff: true}, &got); err != nil {
		t.Fatalf("verify needed a credential: %v", err)
	}
	if len(got.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(got.Entries))
	}
	e := got.Entries[0]
	if e.Status["KEPT"] != "unchanged" {
		t.Errorf("KEPT = %q, want unchanged", e.Status["KEPT"])
	}
	if e.Status["ROTATED"] != "changed" {
		t.Errorf("ROTATED = %q, want changed", e.Status["ROTATED"])
	}
	// The whole point: it answered, and printed nothing.
	if len(e.Values) != 0 {
		t.Fatalf("verify returned values: %v", e.Values)
	}
}
