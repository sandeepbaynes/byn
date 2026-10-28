//go:build byntest

package daemon

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

// An ad hoc request is the whole question on one card: the command, the
// directory, the names, the vault and scope, and who asked. Nothing is left for
// the run to decide that the approver did not see.

// adhocReq builds a request the way the CLI sends one: with the directory it
// is made from. Linux reads the caller's directory from the kernel and ignores
// the claim; macOS has no such read, so the claim is what anchors the request
// there — a test that leaves it out passes on one and not the other.
func adhocReq(vars ...string) ipc.ExecFetchReq {
	return ipc.ExecFetchReq{
		Command: "echo hello", Argv: []string{"echo", "hello"}, Vars: vars,
		Reason: "one-off check", Cwd: testCwd(),
	}
}

func errDetails(t *testing.T, err error) map[string]string {
	t.Helper()
	var er *ipc.ErrResponse
	if !errors.As(err, &er) {
		t.Fatalf("expected an ErrResponse, got %v", err)
	}
	return er.Details
}

func TestAdhoc_RaisesApprovalCarryingTheWholeQuestion(t *testing.T) {
	_ = stubOrigin(t, true)
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "DB_URL", []byte("postgres://x"))

	_, err := execFetch(t, c, adhocReq("DB_URL", "API_KEY", "DB_URL"))
	if code := errCode(t, err); code != ipc.CodeApprovalPending {
		t.Fatalf("code = %v, want approval_pending", code)
	}
	details := errDetails(t, err)
	if details["kind"] != "adhoc" || details["gets"] != "API_KEY,DB_URL" ||
		details["project"] != "default" || details["env"] != "default" {
		t.Errorf("details = %v — a caller handing this to a person needs kind, gets, project, env", details)
	}

	pending := onlyPending(t, c)
	cwd, _ := os.Getwd()
	if pending.Kind != "adhoc" || pending.Vault != "default" ||
		pending.Project != "default" || pending.Env != "default" {
		t.Errorf("card scope = %s/%s/%s kind=%s", pending.Vault, pending.Project, pending.Env, pending.Kind)
	}
	// Sorted and de-duplicated: the fingerprint must not depend on how the
	// names were typed.
	if !slices.Equal(pending.Gets, []string{"API_KEY", "DB_URL"}) {
		t.Errorf("gets = %v, want [API_KEY DB_URL]", pending.Gets)
	}
	if pending.Subject != trust.Canonicalize(cwd) {
		t.Errorf("subject = %q, want this directory %q", pending.Subject, cwd)
	}
	if pending.Beside != "" || pending.HighRisk {
		t.Errorf("no .byn here, but beside=%q high_risk=%v", pending.Beside, pending.HighRisk)
	}
	if len(pending.Summary) != 1 || pending.Summary[0] != "runs echo hello" {
		t.Errorf("summary = %v", pending.Summary)
	}
}

// A wildcard is not a list, and the card lists what a yes hands over.
func TestAdhoc_RefusesAWildcardOrEmptyName(t *testing.T) {
	_ = stubOrigin(t, true)
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	for _, bad := range []string{"*", "", "A B", "DB_URL=x"} {
		_, err := execFetch(t, c, adhocReq(bad))
		if code := errCode(t, err); code != ipc.CodeBadRequest {
			t.Errorf("--var %q: code = %v, want bad_request", bad, code)
		}
	}
	if list := allPending(t, c); len(list) != 0 {
		t.Errorf("a refused request was queued: %+v", list)
	}
}

// The grant is a capability for exactly the names on the card. It opens them
// while the vault is locked, hands over nothing else, and reports a name the
// vault had no value for rather than quietly starting the command without it.
func TestAdhoc_ApprovedGrantRunsLockedWithExactlyTheNamedValues(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "DB_URL", []byte("postgres://x"))
	putVar(t, c, ipc.Scope{}, "API_KEY", []byte("k-1"))
	putVar(t, c, ipc.Scope{}, "EXTRA", []byte("not asked for"))

	req := adhocReq("DB_URL", "API_KEY", "NOT_YET")
	if _, err := execFetch(t, c, req); errCode(t, err) != ipc.CodeApprovalPending {
		t.Fatal("wanted a queued request")
	}
	pending := onlyPending(t, c)
	var resp ipc.ApprovalDecideResp
	if err := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
		ID: pending.ID, Approve: true, Password: pw,
	}, &resp); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// The default window for an ad hoc grant is an hour, not the six a .byn
	// command gets: nothing on disk anchors it.
	if left := time.Until(time.Unix(resp.Entry.GrantedUntil, 0)); left <= 50*time.Minute || left > 65*time.Minute {
		t.Errorf("granted for %s, want about 1h", left)
	}

	lockVaultStore(t, d, "default")
	got, err := execFetch(t, c, req)
	if err != nil {
		t.Fatalf("approved ad hoc run while locked: %v", err)
	}
	m := valueMap(got.Values)
	if m["DB_URL"] != "postgres://x" || m["API_KEY"] != "k-1" {
		t.Errorf("values = %v, want DB_URL and API_KEY", m)
	}
	if _, leaked := m["EXTRA"]; leaked {
		t.Error("EXTRA was injected — the grant must cover only the names on the card")
	}
	if !slices.Contains(got.MissingValues, "NOT_YET") {
		t.Errorf("missing = %v, want NOT_YET reported", got.MissingValues)
	}
	if got.GrantExpiresAt == 0 {
		t.Error("the run did not say when its grant lapses")
	}
}

// The grant answers exactly one question. A different vault, a different
// directory, or one more name is a different question and asks again.
func TestAdhoc_GrantIsBoundToVaultDirectoryAndNames(t *testing.T) {
	_ = stubOrigin(t, true)
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	initNamedLocked(t, c, "mine", []byte("a-vault-i-made-for-myself"))
	putVar(t, c, ipc.Scope{}, "DB_URL", []byte("postgres://x"))

	req := adhocReq("DB_URL")
	if _, err := execFetch(t, c, req); errCode(t, err) != ipc.CodeApprovalPending {
		t.Fatal("wanted a queued request")
	}
	pending := onlyPending(t, c)
	if err := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
		ID: pending.ID, Approve: true, Password: pw,
	}, &ipc.ApprovalDecideResp{}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := execFetch(t, c, req); err != nil {
		t.Fatalf("the approved question itself: %v", err)
	}

	more := adhocReq("DB_URL", "API_KEY")
	if _, err := execFetch(t, c, more); errCode(t, err) != ipc.CodeApprovalPending {
		t.Error("one more name ran on a grant that did not name it")
	}
	other := req
	other.Scope = ipc.Scope{Vault: "mine"}
	if _, err := execFetch(t, c, other); errCode(t, err) != ipc.CodeApprovalPending {
		t.Error("the same command against another vault ran on this vault's grant")
	}
	// Moving the process moves the claim with it, as the CLI's does. Linux
	// anchors the request to the kernel's view of the directory; macOS to the
	// claim; both must see a different directory here.
	elsewhere := t.TempDir()
	t.Chdir(elsewhere)
	moved := req
	moved.Cwd = elsewhere
	if _, err := execFetch(t, c, moved); errCode(t, err) != ipc.CodeApprovalPending {
		t.Error("the same command from another directory ran on this directory's grant")
	}
}

// Beside a trusted .byn, an ad hoc request is allowed and flagged: the card
// names the file it steps around, and the file itself is neither consulted
// nor changed.
func TestAdhoc_BesideATrustedBynIsFlaggedAndLeavesItAlone(t *testing.T) {
	_ = stubOrigin(t, true)
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "DB_URL", []byte("postgres://x"))
	putVar(t, c, ipc.Scope{}, "API_KEY", []byte("k-1"))
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"DB_URL\"]\nactions = [\"pinned run\"]\n")
	grantBynFile(t, c, byn, pw)

	req := adhocReq("API_KEY")
	req.Path = byn
	if _, err := execFetch(t, c, req); errCode(t, err) != ipc.CodeApprovalPending {
		t.Fatal("wanted a queued request")
	}
	pending := onlyPending(t, c)
	if pending.Beside != trust.Canonicalize(byn) || !pending.HighRisk {
		t.Errorf("beside=%q high_risk=%v — the card must say a trusted .byn is being stepped around",
			pending.Beside, pending.HighRisk)
	}

	// The file's own contract is untouched: its pinned command still runs
	// with its own allowlist, and only that.
	got, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "pinned run", Argv: []string{"pinned", "run"},
	})
	if err != nil {
		t.Fatalf("the .byn's pinned command: %v", err)
	}
	if m := valueMap(got.Values); m["DB_URL"] == "" || m["API_KEY"] != "" {
		t.Errorf(".byn run got %v, want DB_URL only", m)
	}
}

// Revoking takes the keys with it; a spent single-use grant too.
func TestAdhoc_RevokeAndOnceEndTheGrant(t *testing.T) {
	_ = stubOrigin(t, true)
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "DB_URL", []byte("postgres://x"))

	req := adhocReq("DB_URL")
	req.AskOnce = true
	if _, err := execFetch(t, c, req); errCode(t, err) != ipc.CodeApprovalPending {
		t.Fatal("wanted a queued request")
	}
	pending := onlyPending(t, c)
	if err := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
		ID: pending.ID, Approve: true, Password: pw,
	}, &ipc.ApprovalDecideResp{}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := execFetch(t, c, req); err != nil {
		t.Fatalf("first run on a single-use grant: %v", err)
	}
	if _, err := execFetch(t, c, req); errCode(t, err) != ipc.CodeApprovalPending {
		t.Error("a single-use grant authorized a second run")
	}

	req.AskOnce = false
	if _, err := execFetch(t, c, req); errCode(t, err) != ipc.CodeApprovalPending {
		t.Fatal("wanted a queued request")
	}
	again := onlyPending(t, c)
	if err := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
		ID: again.ID, Approve: true, Password: pw,
	}, &ipc.ApprovalDecideResp{}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{ID: again.ID, Revoke: true},
		&ipc.ApprovalDecideResp{}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := execFetch(t, c, req); errCode(t, err) != ipc.CodeApprovalPending {
		t.Error("a revoked grant still authorized a run")
	}
}

// A .byn's project is a name inside its own vault. A request naming another
// vault and no project is refused with the hint pointing at that vault's
// default project — not at the file's, which exists only in the file's vault
// — and, with --var, is an ad hoc request in that vault's default scope.
func TestExec_AnotherVaultDoesNotBorrowTheBynsProject(t *testing.T) {
	_ = stubOrigin(t, true)
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	initNamedLocked(t, c, "mine", []byte("a-vault-i-made-for-myself"))
	byn := writeBynContent(t, "[scope]\nproject = \"alpha\"\n\n[exec]\nactions = [\"pinned run\"]\n")
	grantBynFile(t, c, byn, pw)

	run := ipc.ExecFetchReq{
		Path: byn, Command: "pinned run", Argv: []string{"pinned", "run"},
		Scope: ipc.Scope{Vault: "mine"}, Cwd: testCwd(),
	}
	err := mustErr(execFetch(t, c, run))
	if code := errCode(t, err); code != ipc.CodeTrustDenied {
		t.Fatalf("code = %v, want trust_denied", code)
	}
	if strings.Contains(err.Error(), "alpha") || !strings.Contains(err.Error(), "--vault mine --project default --env default") {
		t.Errorf("the hint must name mine's default scope, not the file's project: %v", err)
	}

	run.Vars = []string{"DB_URL"}
	if code := errCode(t, mustErr(execFetch(t, c, run))); code != ipc.CodeApprovalPending {
		t.Fatalf("with --var: code = %v, want approval_pending", code)
	}
	if pending := onlyPending(t, c); pending.Vault != "mine" || pending.Project != "default" {
		t.Errorf("card = vault %s project %s, want mine/default", pending.Vault, pending.Project)
	}
}

// A .byn is the contract for the vault it was trusted into. Asked to run it
// against another vault, byn refuses and says how to ask for that instead;
// with the variables named, the same command line is an ad hoc request in the
// vault that was asked for.
func TestExec_BynTrustedForAnotherVaultIsRefusedUnlessAskedAdhoc(t *testing.T) {
	_ = stubOrigin(t, true)
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	initNamedLocked(t, c, "mine", []byte("a-vault-i-made-for-myself"))
	byn := writeBynContent(t, "[scope]\n\n[exec]\nactions = [\"pinned run\"]\n")
	grantBynFile(t, c, byn, pw)

	run := ipc.ExecFetchReq{
		Path: byn, Command: "pinned run", Argv: []string{"pinned", "run"},
		Scope: ipc.Scope{Vault: "mine"}, Cwd: testCwd(),
	}
	_, err := execFetch(t, c, run)
	if code := errCode(t, err); code != ipc.CodeTrustDenied {
		t.Fatalf("code = %v, want trust_denied", code)
	}
	if !strings.Contains(err.Error(), "trusted for vault default, not mine") ||
		!strings.Contains(err.Error(), "--var NAME") || !strings.Contains(err.Error(), "--no-discovery") {
		t.Errorf("the refusal must say which vault and both ways out: %v", err)
	}
	if list := allPending(t, c); len(list) != 0 {
		t.Fatalf("a refused run queued something: %+v", list)
	}

	run.Vars = []string{"DB_URL"}
	if code := errCode(t, mustErr(execFetch(t, c, run))); code != ipc.CodeApprovalPending {
		t.Fatalf("with --var: code = %v, want approval_pending", code)
	}
	pending := onlyPending(t, c)
	if pending.Kind != "adhoc" || pending.Vault != "mine" || pending.Beside != trust.Canonicalize(byn) {
		t.Errorf("card = kind %s vault %s beside %q", pending.Kind, pending.Vault, pending.Beside)
	}
	// And only mine's password answers it.
	err = c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
		ID: pending.ID, Approve: true, Password: pw,
	}, &ipc.ApprovalDecideResp{})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Errorf("default's password approved a request in mine: %v", err)
	}
}

func mustErr(_ ipc.ExecFetchResp, err error) error { return err }

// The process that raised a card is "whoever asked" before anyone else is.
//
// A CLI waiting on its approval is the same process that asked, yet its
// ancestry can change while it waits: an agent harness that times out or
// backgrounds the tool call kills the shell between byn and the agent, and
// byn is reparented to init. The grant was bound to the agent identity
// recorded at raise time, which that process can no longer prove — so it
// re-raised a fresh card with no identity at all, every two seconds, and
// the approval it had just been given was never used.
func TestAdhoc_TheAskingProcessKeepsItsGrantWhenItsAncestryIsGone(t *testing.T) {
	setShares := stubOrigin(t, true)
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "DB_URL", []byte("postgres://x"))

	req := adhocReq("DB_URL")
	if _, err := execFetch(t, c, req); errCode(t, err) != ipc.CodeApprovalPending {
		t.Fatal("wanted a queued request")
	}
	pending := onlyPending(t, c)
	if pending.Requestor.AgentPID == 0 {
		t.Fatal("test premise: the card must record an agent identity to be bound to")
	}
	var resp ipc.ApprovalDecideResp
	if err := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
		ID: pending.ID, Approve: true, Password: pw,
	}, &resp); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// The shell between byn and the agent is gone; the ancestry walk from
	// this process no longer reaches the recorded agent.
	setShares(false)

	got, err := execFetch(t, c, req)
	if err != nil {
		t.Fatalf("the process that raised the card could not use its own grant: %v", err)
	}
	if m := valueMap(got.Values); m["DB_URL"] != "postgres://x" {
		t.Errorf("values = %v, want DB_URL", m)
	}
	var list ipc.ApprovalListResp
	if err := c.Call(ipc.OpApprovalList, ipc.ApprovalListReq{}, &list); err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, e := range list.Entries {
		if e.Status == "pending" {
			t.Errorf("a second card %s was raised for a question already answered", e.ID)
		}
	}
}

// The same-process rule reaches exactly one process. Another process that
// cannot prove the agent's ancestry either is a stranger, and gets a card of
// its own rather than the grant.
func TestAdhoc_AnotherProcessWithoutTheAncestryGetsNoGrant(t *testing.T) {
	setShares := stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "DB_URL", []byte("postgres://x"))

	req := adhocReq("DB_URL")
	if _, err := execFetch(t, c, req); errCode(t, err) != ipc.CodeApprovalPending {
		t.Fatal("wanted a queued request")
	}
	pending := onlyPending(t, c)
	if err := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
		ID: pending.ID, Approve: true, Password: pw,
	}, new(ipc.ApprovalDecideResp)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	setShares(false)

	// A live process that is not the one that asked: the test runner's parent.
	stranger := withCaller(context.Background(), socketCaller(d.ownerUID, os.Getppid(), nil))
	env, err := ipc.NewRequest("fetch-1", ipc.OpExecFetch, req)
	if err != nil {
		t.Fatal(err)
	}
	resp := d.handleExecFetch(stranger, env)
	if resp.Err == nil {
		t.Fatal("a process with neither the ancestry nor the asker's identity used the grant")
	}
	if resp.Err.Code != ipc.CodeApprovalPending {
		t.Fatalf("code = %s (%s), want approval_pending", resp.Err.Code, resp.Err.Message)
	}
}
