//go:build byntest

package daemon

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// Approving a command is proof of presence for the vault the command runs
// against, and nothing else. A password is only evidence of who you are for the
// vault it unlocks: anyone can create a vault of their own and know its
// password, so accepting one vault's password for another vault's request would
// let any caller approve itself.
func TestApprovalDecide_ActionNeedsThatVaultsPassword(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	// The vault an attacker made for themselves, so they know its password.
	otherPW := []byte("a-vault-i-made-for-myself")
	initNamedLocked(t, c, "mine", otherPW)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nactions = [\"pinned run\"]\n")
	grantBynFile(t, c, byn, pw)
	if _, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "echo hello", Argv: []string{"echo", "hello"},
	}); errCode(t, err) != ipc.CodeApprovalPending {
		t.Fatalf("wanted a queued request")
	}
	pending := onlyPending(t, c)
	if pending.Vault != "default" {
		t.Fatalf("request vault = %q, want default", pending.Vault)
	}

	for name, wrong := range map[string][]byte{
		"another vault's password": otherPW,
		"no vault's password":      []byte("not-a-password-at-all"),
	} {
		err := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
			ID: pending.ID, Approve: true, Password: wrong,
		}, &ipc.ApprovalDecideResp{})
		// The limiter backs off after the first failure, so a second wrong
		// password may be refused as rate-limited instead; either is a refusal.
		if code := errCode(t, err); code != ipc.CodeWrongPassword && code != ipc.CodeRateLimited {
			t.Fatalf("%s: code = %v, want wrong_password", name, code)
		}
	}
	if still := onlyPending(t, c); still.Status != "pending" {
		t.Fatalf("a refused password changed the request to %q", still.Status)
	}

	_ = d.limiter.RecordSuccess() // clear the backoff the wrong passwords earned
	var resp ipc.ApprovalDecideResp
	if err := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
		ID: pending.ID, Approve: true, Password: pw,
	}, &resp); err != nil {
		t.Fatalf("approve with the right password: %v", err)
	}
	if resp.Entry.Status != "approved" {
		t.Fatalf("status = %q, want approved", resp.Entry.Status)
	}
}
