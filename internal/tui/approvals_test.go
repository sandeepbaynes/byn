package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func approvalsModel(entries ...ipc.ApprovalEntry) Model {
	m := NewModel(nil, "test", ipc.Scope{})
	m.Width, m.Height = 100, 40
	m.Mode = ModeApprovals
	m.approvals = entries
	return m
}

// aKey builds a KeyMsg from a name. The package already has key(rune); this
// takes the named keys too, which the reason line needs.
func aKey(s string) tea.KeyMsg {
	switch s {
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// The queue has to show what the asker asked for, not just what it wants to
// run: a single-use request changes what approving DOES, and an approver should
// know that before deciding rather than from the result.
func TestTUIApprovals_ShowsTheSingleUseAsk(t *testing.T) {
	m := approvalsModel(ipc.ApprovalEntry{
		ID: "abc123", Subject: "/p/.byn", Status: "pending", AskOnce: true,
		Summary: []string{"runs make dev"},
	})
	out := m.renderApprovals(100, 30)
	if !strings.Contains(out, "make dev") {
		t.Fatalf("the command must be visible:\n%s", out)
	}
	if !strings.Contains(out, "single use") {
		t.Fatalf("a single-use request must say so:\n%s", out)
	}
}

// The decider's words are typed before answering and attached to whatever
// answer follows, so the reason line must own the keyboard while it is open —
// otherwise "d" denies instead of typing a d.
func TestTUIApprovals_ReasonLineOwnsTheKeyboard(t *testing.T) {
	m := approvalsModel(ipc.ApprovalEntry{ID: "abc123", Status: "pending"})
	m, _ = m.keyApprovals(aKey("r"))
	if !m.approvalTyping {
		t.Fatal("r must open the reason line")
	}
	for _, ch := range []string{"d", "a", "o"} {
		m, _ = m.keyApprovals(aKey(ch))
	}
	if m.approvalReason != "dao" {
		t.Fatalf("keys must type into the reason, got %q", m.approvalReason)
	}
	if m.Mode != ModeApprovals {
		t.Fatal("typing a reason must not trigger a decision")
	}
	m, _ = m.keyApprovals(aKey("enter"))
	if m.approvalTyping {
		t.Fatal("enter must close the reason line")
	}
	if m.approvalReason != "dao" {
		t.Fatal("enter must keep what was typed")
	}
}

// Approving hands out authority, so it goes through the password overlay — the
// same gate the terminal and the portal use.
func TestTUIApprovals_ApproveIsPasswordGated(t *testing.T) {
	m := approvalsModel(ipc.ApprovalEntry{ID: "abc123", Status: "pending"})
	m, _ = m.keyApprovals(aKey("a"))
	if m.Mode != ModeAuthRequired {
		t.Fatalf("approving must ask for the password, mode=%v", m.Mode)
	}
	if m.pendingApproval == nil || m.pendingApproval.ID != "abc123" {
		t.Fatal("the decision must be parked for replay after the password")
	}
	if m.pendingApproval.Once {
		t.Fatal("plain approve must not silently become single-use")
	}
}

// o parks the same decision as single-use.
func TestTUIApprovals_ApproveOnceParksASingleUse(t *testing.T) {
	m := approvalsModel(ipc.ApprovalEntry{ID: "abc123", Status: "pending"})
	m, _ = m.keyApprovals(aKey("o"))
	if m.pendingApproval == nil || !m.pendingApproval.Once {
		t.Fatal("o must park a single-use approval")
	}
}

// Denying and revoking remove authority and so are not password-gated —
// refusing has to stay the cheaper action, or people learn to approve by
// reflex. They must dispatch a command rather than open the auth overlay.
func TestTUIApprovals_DenyNeedsNoPassword(t *testing.T) {
	m := approvalsModel(ipc.ApprovalEntry{ID: "abc123", Status: "pending"})
	m2, cmd := m.keyApprovals(aKey("d"))
	if m2.Mode == ModeAuthRequired {
		t.Fatal("denying must not ask for a password")
	}
	if cmd == nil {
		t.Fatal("denying must actually dispatch a decision")
	}
}

// Revoke only applies where there is a live grant; offering it on a pending
// request would suggest denying and revoking are the same act, and they are not.
func TestTUIApprovals_RevokeRefusesAPendingRequest(t *testing.T) {
	m := approvalsModel(ipc.ApprovalEntry{ID: "abc123", Status: "pending"})
	_, cmd := m.keyApprovals(aKey("v"))
	if cmd != nil {
		t.Fatal("revoke must not act on a request nobody has approved")
	}
}

// A decided request shows its outcome and the words that went with it — the
// history is read to answer "what did it ask for, and what did I say".
func TestTUIApprovals_HistoryShowsOutcomeAndReason(t *testing.T) {
	m := approvalsModel(ipc.ApprovalEntry{
		ID: "abc123", Subject: "/p/.byn", Status: "denied",
		Summary: []string{"runs rm -rf /"}, DecidedReason: "wrong target",
		DecidedVia: "terminal",
	})
	m.approvalHistory = true
	out := m.renderApprovals(100, 30)
	for _, want := range []string{"denied", "wrong target", "terminal"} {
		if !strings.Contains(out, want) {
			t.Errorf("history must show %q:\n%s", want, out)
		}
	}
}
