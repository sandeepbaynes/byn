package main

import (
	"os"
	"strings"
	"testing"
)

// TestSetupRelocateMessage_DoesNotInviteDeletingTheSessionStore.
//
// setup said "relocated legacy ~/.byn -> /var/lib/byn", which reads as: that
// directory is finished with. It is not. Once byn is provisioned the system dir
// is _byn-owned and 0711, so the owner cannot write to it, and per-terminal
// unlock sessions deliberately go on living in the home directory
// (session.StoreDir returns it exactly when provisioned).
//
// The wording matters more than usual here because of what is left in that
// directory: a stale portal.token and daemon.log from before provisioning, next
// to a live sessions/ subtree. Somebody auditing their home directory finds
// files that look like abandoned credentials, reads "relocated legacy", and
// tidies up — deleting their own session store. Both readings lead to `rm -rf`,
// and one of them is wrong.
func TestSetupRelocateMessage_DoesNotInviteDeletingTheSessionStore(t *testing.T) {
	src, err := os.ReadFile("cmd_setup.go")
	if err != nil {
		t.Fatalf("read cmd_setup.go: %v", err)
	}
	s := string(src)
	if strings.Contains(s, `"relocated legacy %s -> %s`) {
		t.Error(`the message still calls the home directory "legacy", which reads as ` +
			`finished with — it still holds the per-terminal session store`)
	}
	if !strings.Contains(s, "still holds your per-terminal unlock sessions") {
		t.Error("after moving the vault, setup must say the home directory keeps a live " +
			"role, or a tidy-up deletes the session store")
	}
}
