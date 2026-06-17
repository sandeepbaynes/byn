package daemon

import (
	"errors"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// TestExecFetch_ForceAuth_RequiresPasswordEvenForPinned verifies the
// --no-privsep contract: ForceAuth makes a trusted, PINNED action require the
// master password every run (no blind trusted-file run), while the same action
// WITHOUT ForceAuth (the privsep path) runs credential-free.
func TestExecFetch_ForceAuth_RequiresPasswordEvenForPinned(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	byn := writeBynContent(t, "[scope]\n\n[exec]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	base := ipc.ExecFetchReq{Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"}}

	// CONTROL: pinned action WITHOUT ForceAuth runs free (the privsep workflow).
	if _, err := execFetch(t, c, base); err != nil {
		t.Fatalf("pinned action without ForceAuth must run free: %v", err)
	}

	// ForceAuth + pinned action, NO password → auth_required (no blind run).
	forced := base
	forced.ForceAuth = true
	_, err := execFetch(t, c, forced)
	var em *ipc.ErrResponse
	if !errors.As(err, &em) || em.Code != ipc.CodeAuthRequired {
		t.Fatalf("ForceAuth pinned without password must be auth_required, got %v", err)
	}

	// ForceAuth + correct password → success (presence verified).
	forced.Password = pw
	if _, err := execFetch(t, c, forced); err != nil {
		t.Fatalf("ForceAuth with the master password must succeed: %v", err)
	}
}
