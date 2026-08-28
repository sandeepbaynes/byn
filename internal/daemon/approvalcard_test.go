//go:build byntest

package daemon

import (
	"strings"
	"testing"

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
