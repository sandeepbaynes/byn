package ui

import (
	"net/http"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func postDecide(t *testing.T, body string) ipc.ApprovalDecideReq {
	t.Helper()
	// The rules — what once and always mean together, whether a reason is
	// required — live in the daemon, so a tap in the portal and
	// `byn approve <id>` cannot mean different things. What the portal owes is
	// carrying the fields faithfully, and that is what this asserts.
	lastApprovalDecide = ipc.ApprovalDecideReq{}
	ts, c := newTestServer(t, &fakeDisp{})
	defer ts.Close()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/approvals/decide", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:2967")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decide returned %d", resp.StatusCode)
	}
	return lastApprovalDecide
}

// The decider's reason has to reach the daemon, because that is the only route
// by which it reaches the asker: a refusal without one leaves an agent guessing
// between "fix it and ask again" and "stop".
func TestPortalDecide_CarriesTheReason(t *testing.T) {
	got := postDecide(t, `{"id":"abc","approve":false,"reason":"wrong target"}`)
	if got.ID != "abc" || got.Approve {
		t.Fatalf("wrong decision relayed: %+v", got)
	}
	if got.Reason != "wrong target" {
		t.Fatalf("reason not relayed, got %q", got.Reason)
	}
	if got.Via != "portal" {
		t.Fatalf("the surface must be recorded as portal, got %q", got.Via)
	}
}

// once and always are sent as a pair and resolved by the daemon. The portal must
// not collapse them into one boolean on the way, or "do what the asker asked
// for" becomes unexpressible and every plain approval silently overrides it.
func TestPortalDecide_CarriesBothOverridesSeparately(t *testing.T) {
	for _, tc := range []struct {
		name, body           string
		wantOnce, wantAlways bool
	}{
		{"neither: honour the ask", `{"id":"a","approve":true}`, false, false},
		{"once", `{"id":"a","approve":true,"once":true}`, true, false},
		{"always", `{"id":"a","approve":true,"always":true}`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := postDecide(t, tc.body)
			if got.Once != tc.wantOnce || got.Always != tc.wantAlways {
				t.Fatalf("once=%v always=%v, want once=%v always=%v",
					got.Once, got.Always, tc.wantOnce, tc.wantAlways)
			}
		})
	}
}

// Revoke had no portal route at all: a grant given from the browser could only
// be taken back from a terminal.
func TestPortalDecide_CanRevoke(t *testing.T) {
	got := postDecide(t, `{"id":"abc","revoke":true}`)
	if !got.Revoke {
		t.Fatal("revoke not relayed")
	}
	if len(got.Password) != 0 {
		t.Fatal("revoking must not require a password — it only ever removes authority")
	}
}

// A decode failure must not become a silently-empty decision.
func TestPortalDecide_RejectsMalformedBody(t *testing.T) {
	// The rules — what once and always mean together, whether a reason is
	// required — live in the daemon, so a tap in the portal and
	// `byn approve <id>` cannot mean different things. What the portal owes is
	// carrying the fields faithfully, and that is what this asserts.
	lastApprovalDecide = ipc.ApprovalDecideReq{}
	ts, c := newTestServer(t, &fakeDisp{})
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/approvals/decide", strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:2967")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for malformed JSON, got %d", resp.StatusCode)
	}
	if lastApprovalDecide.ID != "" {
		t.Fatal("a malformed body must not reach the daemon as a decision")
	}
}
