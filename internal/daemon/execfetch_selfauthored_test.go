package daemon

import (
	"errors"
	"os"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// A variable the caller created itself is not a secret being disclosed to it.
// These cover the line between that and a genuine widening.

// stubOrigin pins the process-identity lookups so a single test process can act
// as one consistent agent. The lookups themselves are covered against the real
// process tree in procorigin_test.go.
func stubOrigin(t *testing.T, shares bool) func(bool) {
	t.Helper()
	origCaller, origShares := callerOriginFn, sharesOriginFn
	t.Cleanup(func() { callerOriginFn, sharesOriginFn = origCaller, origShares })
	callerOriginFn = func(int) procRef { return procRef{PID: 4242, Start: 99} }
	current := shares
	sharesOriginFn = func(int, procRef) bool { return current }
	// The returned setter lets one test be the agent for a while and then a
	// stranger — which is how "someone else replaced the value" is expressed,
	// since a single test process is only ever one real origin.
	return func(v bool) { current = v }
}

// putVarUnattended stores a value the way an AGENT does: over a connection
// carrying no session, because sessions are minted by `byn unlock` and bound to
// a terminal, and an agent has none. byn treats such a write as unattended,
// which is what earns the caller the right to read and replace it later.
func putVarUnattended(t *testing.T, c *ipc.Client, scope ipc.Scope, name string, value []byte) {
	t.Helper()
	held := c.Session
	c.Session = nil
	defer func() { c.Session = held }()
	putVar(t, c, scope, name, value)
}

// rewriteByn replaces a .byn's content in place, the way an agent editing the
// file does. Distinct from appendToFile, which produces a duplicate key.
func rewriteByn(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// authoredNames returns the variables byn has recorded this caller as having
// authored, across every trust record. The deny tests assert on it so they
// cannot pass for an unrelated reason — an earlier version of this file did
// exactly that, denying on a broken timestamp comparison rather than on the
// rule under test.
func authoredNames(t *testing.T, d *Daemon) []string {
	t.Helper()
	return d.authored.NamesFor(vault.DefaultVaultName, vault.DefaultProjectName, vault.DefaultEnvName)
}

func hasAuthored(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// The headline case: an agent invents a value, stores it, wires it into .byn,
// and runs. Nothing here is a disclosure — byn is handing back what the caller
// supplied — so it must not stop for a human.
func TestSelfAuthored_AgentAddsTheVariableItJustCreated(t *testing.T) {
	_ = stubOrigin(t, true)
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	// The agent's own loop: create the value, then declare it.
	putVarUnattended(t, c, ipc.Scope{}, "API_TOKEN", []byte("tok-agent-made"))
	rewriteByn(t, byn, "[scope]\n\n[exec]\nenv = [\"SEED\", \"API_TOKEN\"]\nactions = [\"mytool run\"]\n")

	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"},
	})
	if err != nil {
		t.Fatalf("a caller must be able to read back a value it created: %v", err)
	}
	if m := valueMap(resp.Values); m["API_TOKEN"] != "tok-agent-made" {
		t.Fatalf("API_TOKEN = %q, want tok-agent-made; values=%v", m["API_TOKEN"], m)
	}
}

// The boundary that matters: a secret that already existed is not covered by
// authorship, so exposing it to the project's commands still needs a human.
func TestSelfAuthored_PreExistingSecretStillNeedsApproval(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Created BEFORE the grant — the case authorship must never cover.
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	putVarUnattended(t, c, ipc.Scope{}, "AWS_SECRET", []byte("pre-existing"))
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	rewriteByn(t, byn, "[scope]\n\n[exec]\nenv = [\"SEED\", \"AWS_SECRET\"]\nactions = [\"mytool run\"]\n")

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"},
	})
	if code := errCode(t, err); code != ipc.CodeApprovalPending {
		t.Fatalf("code = %v, want approval_pending — a secret that predates the grant is a real widening", code)
	}
	// And for the right reason. byn records authorship for every create, even
	// one made before any .byn was trusted, so the refusal cannot be coming
	// from a missing record — it comes from the value predating the grant.
	if names := authoredNames(t, d); !hasAuthored(names, "AWS_SECRET") {
		t.Fatalf("precondition: creating AWS_SECRET should record authorship; authored=%v", names)
	}
}

// An overwrite is authorization-gated because it may install a value the
// original author never saw. Authorship must not survive one.
func TestSelfAuthored_OverwrittenValueStillNeedsApproval(t *testing.T) {
	setShares := stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	putVarUnattended(t, c, ipc.Scope{}, "SHARED", []byte("agent-placeholder"))
	if names := authoredNames(t, d); !hasAuthored(names, "SHARED") {
		t.Fatalf("precondition: creating SHARED should record authorship; authored=%v", names)
	}
	// SOMEONE ELSE, holding the password, replaces it — the case that matters.
	// The author's own overwrite is allowed and keeps authorship; a stranger's
	// must take it away, or the agent could have a person install the real
	// credential and then read it back as its own.
	setShares(false)
	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "SHARED", Value: []byte("real-production-key"), Password: pw,
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	setShares(true)
	rewriteByn(t, byn, "[scope]\n\n[exec]\nenv = [\"SEED\", \"SHARED\"]\nactions = [\"mytool run\"]\n")

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"},
	})
	if code := errCode(t, err); code != ipc.CodeApprovalPending {
		t.Fatalf("code = %v, want approval_pending — an overwritten value is no longer the author's", code)
	}
	if names := authoredNames(t, d); hasAuthored(names, "SHARED") {
		t.Errorf("the overwrite must revoke authorship of SHARED; authored=%v", names)
	}
}

// Deleting the value revokes authorship of the name, so a later value that
// happens to reuse it does not arrive pre-approved.
func TestSelfAuthored_DeleteRevokesAuthorship(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	putVarUnattended(t, c, ipc.Scope{}, "TEMP", []byte("scratch"))
	if names := authoredNames(t, d); !hasAuthored(names, "TEMP") {
		t.Fatalf("precondition: creating TEMP should record authorship; authored=%v", names)
	}
	if err := c.Call(ipc.OpDelete, ipc.DeleteReq{
		Scope: ipc.Scope{}, Name: "TEMP", Password: pw,
	}, &ipc.DeleteResp{}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if names := authoredNames(t, d); hasAuthored(names, "TEMP") {
		t.Errorf("deleting TEMP must revoke its authorship; authored=%v", names)
	}
}

// The exemption follows the caller, not the machine: another terminal, editor
// window, or service does not inherit it.
func TestSelfAuthored_DifferentOriginStillNeedsApproval(t *testing.T) {
	_ = stubOrigin(t, false) // records authorship, but this caller is a stranger
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	putVarUnattended(t, c, ipc.Scope{}, "OTHERS_VAR", []byte("not-yours"))
	rewriteByn(t, byn, "[scope]\n\n[exec]\nenv = [\"SEED\", \"OTHERS_VAR\"]\nactions = [\"mytool run\"]\n")

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"},
	})
	if code := errCode(t, err); code != ipc.CodeApprovalPending {
		t.Fatalf("code = %v, want approval_pending — a different origin must not inherit the grant", code)
	}
}

// The grant has to survive a locked vault, which is the state autonomous exec
// actually runs in. This is what the capability refresh at put time is for:
// without it the name is allowed but decrypts to nothing.
func TestSelfAuthored_InjectsWhileLocked(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	putVarUnattended(t, c, ipc.Scope{}, "API_TOKEN", []byte("tok-agent-made"))
	rewriteByn(t, byn, "[scope]\n\n[exec]\nenv = [\"SEED\", \"API_TOKEN\"]\nactions = [\"mytool run\"]\n")

	lockVaultStore(t, d, "default")

	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"},
	})
	if err != nil {
		t.Fatalf("locked autonomous exec must still inject a self-authored var: %v", err)
	}
	m := valueMap(resp.Values)
	if m["API_TOKEN"] != "tok-agent-made" {
		t.Fatalf("API_TOKEN = %q, want tok-agent-made while LOCKED; values=%v", m["API_TOKEN"], m)
	}
	if m["SEED"] != "seed-val" {
		t.Errorf("refreshing the capability must not drop the originally granted vars: %v", m)
	}
}

// The same flow with NOTHING stubbed, so the real origin lookup runs against
// the real process tree.
//
// The stubbed tests above prove the rule; they cannot prove that byn can
// actually identify a caller, because they replace the code that does it. That
// gap is not theoretical: on a real install the daemon could not read the
// caller's /proc at all, so this path returned "no usable origin" every time
// and every self-authored variable still asked for approval — with the stubbed
// tests passing throughout.
func TestSelfAuthored_RealOriginLookup(t *testing.T) {
	if !callerOrigin(os.Getpid()).ok() {
		t.Skip("no usable parent origin in this environment (reparented to init?)")
	}
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	putVarUnattended(t, c, ipc.Scope{}, "REAL_ORIGIN_TOKEN", []byte("tok-real"))
	// If byn cannot see who the caller is, it records no authorship — the exact
	// shape of the production failure.
	if names := authoredNames(t, d); !hasAuthored(names, "REAL_ORIGIN_TOKEN") {
		t.Fatalf("byn did not identify the caller that created the variable; authored=%v", names)
	}

	rewriteByn(t, byn, "[scope]\n\n[exec]\nenv = [\"SEED\", \"REAL_ORIGIN_TOKEN\"]\nactions = [\"mytool run\"]\n")
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"},
	})
	if err != nil {
		t.Fatalf("real origin match failed: %v", err)
	}
	if m := valueMap(resp.Values); m["REAL_ORIGIN_TOKEN"] != "tok-real" {
		t.Fatalf("REAL_ORIGIN_TOKEN = %q, want tok-real; values=%v", m["REAL_ORIGIN_TOKEN"], m)
	}
}

// Approving an unpinned command must let it RUN.
//
// The queue's whole promise is "the work resumes once someone answers". A
// decision that is recorded and applied to nothing breaks that promise in the
// worst way: the caller is told approval was granted and is stopped at the same
// gate on its next attempt, forever, with a fresh id each time. The existing
// tests checked that approving returned success — not that anything changed.
func TestApprovedUnpinnedCommand_ActuallyRuns(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"pinned run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	fetch := func() (ipc.ExecFetchResp, error) {
		return execFetch(t, c, ipc.ExecFetchReq{
			Path: byn, Command: "cleanup --all", Argv: []string{"cleanup", "--all"},
		})
	}

	_, err := fetch()
	if code := errCode(t, err); code != ipc.CodeApprovalPending {
		t.Fatalf("first attempt: code = %v, want approval_pending", code)
	}
	var list ipc.ApprovalListResp
	if lerr := c.Call(ipc.OpApprovalList, ipc.ApprovalListReq{}, &list); lerr != nil {
		t.Fatalf("approval list: %v", lerr)
	}
	if len(list.Entries) != 1 {
		t.Fatalf("want exactly one pending decision, got %d", len(list.Entries))
	}
	if derr := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
		ID: list.Entries[0].ID, Approve: true, Password: pw,
	}, &ipc.ApprovalDecideResp{}); derr != nil {
		t.Fatalf("approve: %v", derr)
	}

	resp, err := fetch()
	if err != nil {
		t.Fatalf("after approval the command must run, got: %v", err)
	}
	if m := valueMap(resp.Values); m["SEED"] != "seed-val" {
		t.Errorf("SEED = %q, want seed-val", m["SEED"])
	}

	// And it keeps running: an agent retrying, or a build loop, must not have to
	// re-ask for the same command it was just granted.
	if _, err := fetch(); err != nil {
		t.Fatalf("a granted command must keep running, got: %v", err)
	}
}

// Doctor must report whether the daemon can resolve its caller, because when it
// cannot, two features fail silently and nothing else says so.
//
// The check is deliberately a measurement rather than an inspection of /proc
// mount options: the daemon's own sandboxing lives in its mount namespace, so a
// client examining its own /proc sees nothing wrong and reports a confident,
// wrong OK. That is precisely how the real failure went unnoticed.
func TestDoctorReportsWhetherTheDaemonSeesItsCaller(t *testing.T) {
	_, c := startTestDaemon(t)
	var resp ipc.DoctorResp
	if err := c.Call(ipc.OpDoctor, ipc.DoctorReq{}, &resp); err != nil {
		t.Fatalf("doctor: %v", err)
	}
	var found *ipc.DoctorCheck
	for i := range resp.Checks {
		if resp.Checks[i].Name == "daemon.sees_caller" {
			found = &resp.Checks[i]
		}
	}
	if found == nil {
		t.Fatal("doctor does not report daemon.sees_caller")
	}
	// In-process over a real socket, the daemon can read the caller, so this is
	// the healthy branch. The warn branch is what a sandboxed unit produces.
	if found.Severity != "ok" {
		t.Errorf("severity = %q (%s), want ok — the daemon should resolve a caller it shares a /proc with",
			found.Severity, found.Detail)
	}
}

// The workflow this is all for, end to end, against a LOCKED vault:
// an agent creates a value, updates it, reads it back, and starts a service
// with it — without a password at any step, and without the vault being opened.
func TestLockedVault_AgentCreatesUpdatesReadsAndRuns(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// A human trusts the project once, while present. That grant is what hands
	// the machine the ability to write on the agent's behalf afterwards.
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\", \"AGENT_TOKEN\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	// Everything from here happens with the vault LOCKED and no credentials —
	// which means no session either. A real agent has none: sessions are minted
	// by `byn unlock` and bound to a terminal, and an agent has no terminal to
	// bind one to. Dropping the token models that; keeping it would have tested
	// a caller that byn considers attended.
	lockVaultStore(t, d, "default")
	c.Session = nil

	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "AGENT_TOKEN", Value: []byte("tok-v1"),
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("an agent must be able to store a value it invented, locked vault or not: %v", err)
	}
	// Updating its own value — the agent changed its mind about the value it
	// itself chose, which discloses nothing.
	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "AGENT_TOKEN", Value: []byte("tok-v2"),
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("an agent must be able to update the value it created: %v", err)
	}
	var got ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Scope: ipc.Scope{}, Name: "AGENT_TOKEN"}, &got); err != nil {
		t.Fatalf("an agent must be able to read back the value it created: %v", err)
	}
	if string(got.Value) != "tok-v2" {
		t.Fatalf("read back %q, want tok-v2", got.Value)
	}

	// And the service it is building actually receives it.
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"},
	})
	if err != nil {
		t.Fatalf("exec on a locked vault: %v", err)
	}
	m := valueMap(resp.Values)
	if m["AGENT_TOKEN"] != "tok-v2" {
		t.Fatalf("AGENT_TOKEN = %q, want tok-v2 — a value written while locked must still be injected; values=%v", m["AGENT_TOKEN"], m)
	}
	if m["SEED"] != "seed-val" {
		t.Errorf("the ordinary allowlisted vars must keep working alongside: %v", m)
	}
}

// The other half of the bargain: writing while locked must not become a way to
// READ what was already in the vault.
func TestLockedVault_GivesNoAccessToPreExistingSecrets(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	putVarUnattended(t, c, ipc.Scope{}, "AWS_SECRET", []byte("pre-existing"))
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"AWS_SECRET\"]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)
	lockVaultStore(t, d, "default")
	c.Session = nil

	// The caller "authored" AWS_SECRET in the sense that this process created
	// it — but it was written under the vault key, so the locked daemon holds
	// nothing that opens it, and the read must be gated rather than served.
	var got ipc.GetResp
	err := c.Call(ipc.OpGet, ipc.GetReq{Scope: ipc.Scope{}, Name: "AWS_SECRET"}, &got)
	if err == nil {
		t.Fatalf("a locked vault handed back a secret written under the vault key: %q", got.Value)
	}
	// Either refusal is correct — unauthorized, or authorized but with the vault
	// still shut. What matters is that the authored key did not open it, so the
	// assertion is on the outcome rather than on which of the two byn reports.
	if code := errCode(t, err); code != ipc.CodeAuthRequired && code != ipc.CodeLocked {
		t.Fatalf("code = %v, want auth_required or locked", code)
	}
	if len(got.Value) != 0 {
		t.Fatalf("a value came back alongside the error: %q", got.Value)
	}
}

// A value stored while locked must keep working once the vault is opened.
//
// The two paths decrypt differently — the locked one through the scope's
// authored key, the unlocked one through the vault key — so "it worked while
// locked" says nothing about what happens after someone unlocks. A service that
// started fine at 3am and lost a credential when its owner sat down would be a
// nasty way to find that out.
func TestLockedVault_ValueSurvivesA_LaterUnlock(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"AGENT_TOKEN\"]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)
	lockVaultStore(t, d, "default")
	held := c.Session
	c.Session = nil

	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "AGENT_TOKEN", Value: []byte("tok-locked"),
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("locked put: %v", err)
	}

	// The owner sits down and unlocks.
	c.Session = held
	var unlockResp ipc.VaultUnlockResp
	tok, err := c.CallAndCaptureSession(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &unlockResp, nil)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	c.Session = tok

	resp, ferr := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"},
	})
	if ferr != nil {
		t.Fatalf("exec after unlock: %v", ferr)
	}
	if m := valueMap(resp.Values); m["AGENT_TOKEN"] != "tok-locked" {
		t.Fatalf("AGENT_TOKEN = %q, want tok-locked — a value written while locked must survive the unlock; values=%v",
			m["AGENT_TOKEN"], m)
	}
	// And the owner can read it directly, so nothing an agent writes is beyond
	// the reach of the master password.
	var got ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Scope: ipc.Scope{}, Name: "AGENT_TOKEN", Password: pw}, &got); err != nil {
		t.Fatalf("owner get after unlock: %v", err)
	}
	if string(got.Value) != "tok-locked" {
		t.Fatalf("owner read %q, want tok-locked", got.Value)
	}
}

// A STALE session token must not make an agent look attended.
//
// This is what actually broke it on a real machine. The CLI keeps its session
// token on disk and sends it with every call, so one left behind by an earlier
// unlock — the daemon has since restarted, the session expired, someone ran
// `byn lock` — arrives on requests that have no human behind them at all.
// Treating "a token was sent" as "a person is here" put `byn put` straight back
// to demanding a password on a locked vault: the exact symptom the unattended
// path exists to remove.
//
// No existing test could catch it, because tests build their clients fresh and
// never carry a dead token.
func TestStaleSessionDoesNotCountAsAttended(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"AGENT_TOKEN\"]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)
	lockVaultStore(t, d, "default")

	// A token from a daemon that no longer exists — what the CLI keeps on disk
	// and goes on sending after a restart. It is well-formed and completely
	// dead, and the client has no way to know that.
	c.Session = []byte("0123456789abcdef0123456789abcdef")

	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "AGENT_TOKEN", Value: []byte("tok"),
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("a dead session token must not block an unattended write: %v", err)
	}
	var got ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Scope: ipc.Scope{}, Name: "AGENT_TOKEN"}, &got); err != nil {
		t.Fatalf("read-back with the same dead token: %v", err)
	}
	if string(got.Value) != "tok" {
		t.Fatalf("read back %q, want tok", got.Value)
	}
}

// A paused command must carry its facts as data, not only in the sentence.
func TestApprovalPendingCarriesMachineReadableDetails(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"pinned run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "cleanup --all", Argv: []string{"cleanup", "--all"},
	})
	var em *ipc.ErrResponse
	if !errors.As(err, &em) {
		t.Fatalf("want an error response, got %v", err)
	}
	if em.Code != ipc.CodeApprovalPending {
		t.Fatalf("code = %v, want approval_pending", em.Code)
	}
	id := em.Details["approval_id"]
	if id == "" {
		t.Fatal("no approval_id in details — a caller would have to parse it out of the message")
	}
	// The id must be the real one, not something that merely looks like one.
	var list ipc.ApprovalListResp
	if lerr := c.Call(ipc.OpApprovalList, ipc.ApprovalListReq{}, &list); lerr != nil {
		t.Fatalf("approval list: %v", lerr)
	}
	if len(list.Entries) != 1 || list.Entries[0].ID != id {
		t.Fatalf("details id %q does not match the queued request %+v", id, list.Entries)
	}
	if em.Details["command"] != "cleanup --all" {
		t.Errorf("command = %q, want \"cleanup --all\"", em.Details["command"])
	}
	if em.Details["byn"] == "" {
		t.Error("details should name the .byn the decision is about")
	}
	if em.Details["expires_at"] == "" {
		t.Error("details should say when the request expires")
	}
}
