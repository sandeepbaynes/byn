//go:build byntest

package daemon

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// --var naming only unsecure values is answered at once; one sealed name makes
// it a question for a person again.
func TestAdhoc_AllUnsecureNeedsNoApproval(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	putUnsecure(t, c, ipc.Scope{}, "PORT", "8080")
	putUnsecure(t, c, ipc.Scope{}, "REGION", "eu")
	putVar(t, c, ipc.Scope{}, "API_KEY", []byte("s3cret"))
	lockVaultStore(t, d, "default")

	asStranger(c, func() {
		resp, err := execFetch(t, c, adhocReq("PORT", "REGION"))
		if err != nil {
			t.Fatalf("ad hoc for unsecure names only: %v", err)
		}
		if m := valueMap(resp.Values); m["PORT"] != "8080" || m["REGION"] != "eu" {
			t.Fatalf("values = %v", m)
		}
		_, err = execFetch(t, c, adhocReq("PORT", "API_KEY"))
		if code := errCode(t, err); code != ipc.CodeApprovalPending {
			t.Fatalf("with a sealed name: code = %v, want approval_pending", code)
		}
	})
}
