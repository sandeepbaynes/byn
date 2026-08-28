package daemon

import (
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

// A variable the caller created itself is not a secret being disclosed to it.
// These cover the line between that and a genuine widening.

// stubOrigin pins the process-identity lookups so a single test process can act
// as one consistent agent. The lookups themselves are covered against the real
// process tree in procorigin_test.go.
func stubOrigin(t *testing.T, shares bool) func(bool) {
	t.Helper()
	origCaller, origAncestry, origShares := callerOriginFn, callerAncestryFn, sharesAncestryFn
	t.Cleanup(func() {
		callerOriginFn, callerAncestryFn, sharesAncestryFn = origCaller, origAncestry, origShares
	})
	callerOriginFn = func(int) procRef { return procRef{PID: 4242, Start: 99} }
	callerAncestryFn = func(int) []procRef { return []procRef{{PID: 4242, Start: 99}} }
	current := shares
	sharesAncestryFn = func(int, []procRef) bool { return current }
	// The returned setter lets one test be the agent for a while and then a
	// stranger — which is how "someone else replaced the value" is expressed,
	// since a single test process is only ever one real ancestry.
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

// A project can reserve names for a person.
//
// Raised by an agent using byn in anger, from a real incident shape: an agent
// silences "no value for INTEGRATION_CONFIG_ENCRYPTION_KEY" by inventing one,
// the service starts cleanly, and it encrypts data with a key nobody can
// reproduce. byn cannot tell an invented value from a provisioned one, so a
// repo that provisions its secrets by hand needs a way to say so.
func TestUnattendedPut_RespectsAgentPutFalse(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nagent_put = false\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)
	lockVaultStore(t, d, "default")
	c.Session = nil

	err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "ENCRYPTION_KEY", Value: []byte("invented"),
	}, &ipc.PutResp{})
	if err == nil {
		t.Fatal("agent_put = false must stop an unattended write")
	}
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("code = %v, want auth_required", code)
	}
	// And it must say WHY, or the agent cannot tell this from a missing grant.
	var em *ipc.ErrResponse
	if errors.As(err, &em) && !strings.Contains(em.Message, "agent_put") {
		t.Errorf("message %q should name the setting that refused it", em.Message)
	}
}

// The narrower form: most names are fine for an agent to invent, a few are not.
func TestUnattendedPut_RespectsAgentPutDenyList(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\n"+
		"agent_put_deny = [\"ENCRYPTION_KEY\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)
	lockVaultStore(t, d, "default")
	c.Session = nil

	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "ENCRYPTION_KEY", Value: []byte("invented"),
	}, &ipc.PutResp{}); err == nil {
		t.Fatal("a denied name must not be creatable unattended")
	}
	// Everything else still flows, or the gate would cost more than it saves.
	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "TEMP_TABLE", Value: []byte("t_123"),
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("a name not on the deny list must still be storable: %v", err)
	}
}

// Visibility is the other half, and the more important one: the default stays
// permissive, so byn must never hide which values arrived unattended.
func TestUnattendedPut_IsVisible(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("provisioned-by-a-person"))
	grantBynFile(t, c, byn, pw)
	lockVaultStore(t, d, "default")
	c.Session = nil

	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "AGENT_MADE", Value: []byte("invented"),
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	var list ipc.ListResp
	if err := c.Call(ipc.OpList, ipc.ListReq{}, &list); err != nil {
		t.Fatalf("list: %v", err)
	}
	seen := map[string]bool{}
	for _, s := range list.Secrets {
		seen[s.Name] = s.Unattended
	}
	if !seen["AGENT_MADE"] {
		t.Error("a value stored with no credential must be marked unattended in the listing")
	}
	if seen["SEED"] {
		t.Error("a value stored WITH a session must not be marked unattended")
	}

	// And the audit log must name it as its own kind of event.
	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 50}, &tail); err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	var found bool
	for _, e := range tail.Events {
		if e.Op == "put.unattended" && e.EntryName == "AGENT_MADE" {
			found = true
		}
		if e.Op == "put.unattended" && e.EntryName == "SEED" {
			t.Error("an attended put was logged as unattended")
		}
	}
	if !found {
		t.Error("no put.unattended event for the agent-stored value")
	}
}

// The pre-flight: answer "will this run cleanly?" before anything starts.
func TestExecPreflight(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\n"+
		"env = [\"SEED\", \"NEVER_SET\", \"OPTIONAL_ONE\"]\n"+
		"optional = [\"OPTIONAL_ONE\"]\n"+
		"actions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	preflight := func(argv ...string) ipc.ExecPreflightResp {
		t.Helper()
		var r ipc.ExecPreflightResp
		if err := c.Call(ipc.OpExecPreflight, ipc.ExecPreflightReq{Path: byn, Argv: argv}, &r); err != nil {
			t.Fatalf("preflight %v: %v", argv, err)
		}
		return r
	}

	t.Run("pinned command names the pattern that matched", func(t *testing.T) {
		r := preflight("mytool", "run")
		if !r.Pinned {
			t.Fatalf("pinned = false, want true (reason %q, actions %v)", r.Reason, r.Actions)
		}
		if r.MatchedAction != "mytool run" {
			t.Errorf("matched_action = %q, want \"mytool run\" — a caller needs to know which line did it",
				r.MatchedAction)
		}
	})

	t.Run("unpinned says why, and what IS pinned", func(t *testing.T) {
		r := preflight("cleanup", "--all")
		if r.Pinned {
			t.Fatal("pinned = true for a command the .byn does not pin")
		}
		if r.Reason != "no_match" {
			t.Errorf("reason = %q, want no_match — the next step differs from no_actions", r.Reason)
		}
		if len(r.Actions) == 0 {
			t.Error("actions should list what IS pinned, so the near miss is visible")
		}
	})

	t.Run("reports the env gap, minus optional", func(t *testing.T) {
		r := preflight("mytool", "run")
		if len(r.MissingEnv) != 1 || r.MissingEnv[0] != "NEVER_SET" {
			t.Fatalf("missing_env = %v, want [NEVER_SET] — OPTIONAL_ONE is marked optional and SEED has a value",
				r.MissingEnv)
		}
	})

	t.Run("asking must not queue a decision", func(t *testing.T) {
		// The whole point of a pre-flight is that it changes nothing. If asking
		// what would happen raised an approval, checking would become its own
		// source of noise for whoever answers them.
		var list ipc.ApprovalListResp
		if err := c.Call(ipc.OpApprovalList, ipc.ApprovalListReq{}, &list); err != nil {
			t.Fatalf("approval list: %v", err)
		}
		if len(list.Entries) != 0 {
			t.Fatalf("pre-flight queued %d decision(s); it must ask nobody anything", len(list.Entries))
		}
	})
}

// A pre-flight that disagreed with the gate it predicts would be worse than
// none, because it would be believed. Both must use the same matcher.
func TestExecPreflightAgreesWithTheRealGate(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\n"+
		"actions = [\"mytool run\", \"other {{args}}\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	for _, argv := range [][]string{
		{"mytool", "run"},
		{"other", "a", "b"},
		{"cleanup", "--all"},
		{"mytool"},
	} {
		var pre ipc.ExecPreflightResp
		if err := c.Call(ipc.OpExecPreflight, ipc.ExecPreflightReq{Path: byn, Argv: argv}, &pre); err != nil {
			t.Fatalf("preflight %v: %v", argv, err)
		}
		_, err := execFetch(t, c, ipc.ExecFetchReq{
			Path: byn, Command: strings.Join(argv, " "), Argv: argv,
		})
		ranFree := err == nil
		if pre.Pinned != ranFree {
			t.Errorf("argv %v: preflight said pinned=%v, the gate said %v (err=%v)",
				argv, pre.Pinned, ranFree, err)
		}
	}
}

// A refusal must be a wall, not a fresh id.
//
// Re-asking a person who just said no is how approval fatigue starts, and the
// caller learns nothing from an id it did not earn. It must be told when it was
// refused, and why if a reason was given, so it can choose between fixing the
// cause and stopping.
func TestDeniedCommand_IsAWallUntilForceAsk(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"pinned run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	fetch := func(force bool) error {
		_, err := execFetch(t, c, ipc.ExecFetchReq{
			Path: byn, Command: "cleanup --all", Argv: []string{"cleanup", "--all"}, ForceAsk: force,
		})
		return err
	}

	if code := errCode(t, fetch(false)); code != ipc.CodeApprovalPending {
		t.Fatalf("first attempt: code = %v, want approval_pending", code)
	}
	var list ipc.ApprovalListResp
	if err := c.Call(ipc.OpApprovalList, ipc.ApprovalListReq{}, &list); err != nil {
		t.Fatalf("approval list: %v", err)
	}
	if err := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
		ID: list.Entries[0].ID, Approve: false, Reason: "wrong target",
	}, &ipc.ApprovalDecideResp{}); err != nil {
		t.Fatalf("deny: %v", err)
	}

	err := fetch(false)
	if code := errCode(t, err); code == ipc.CodeApprovalPending {
		t.Fatal("a refused command raised a fresh request; a refusal must stop it")
	}
	var em *ipc.ErrResponse
	if !errors.As(err, &em) {
		t.Fatalf("want an error response, got %v", err)
	}
	if !strings.Contains(em.Message, "wrong target") {
		t.Errorf("message %q should carry the reason the decider gave", em.Message)
	}
	if em.Details["denied_at"] == "" {
		t.Error("details should say when it was refused, so the caller can act on it")
	}
	if em.Details["reason"] != "wrong target" {
		t.Errorf("details reason = %q, want the decider's words", em.Details["reason"])
	}

	// --force-ask is the way back, for the human who denied by mistake.
	if code := errCode(t, fetch(true)); code != ipc.CodeApprovalPending {
		t.Fatalf("--force-ask: code = %v, want approval_pending — it must be able to ask again", code)
	}
}

// Deny entries are globs. A real project has dozens of secret-shaped names and
// gains more; a literal list drifts out of date in a week, and a deny list that
// is out of date is worse than none because it reads as protection.
func TestAgentPutDeny_AcceptsGlobs(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\n"+
		"agent_put_deny = [\"*_SECRET\", \"AWS_*\", \"PMS_CONFIG_ENCRYPTION_KEY\"]\n"+
		"actions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)
	lockVaultStore(t, d, "default")
	c.Session = nil

	denied := []string{"STRIPE_SECRET", "AWS_ACCESS_KEY_ID", "PMS_CONFIG_ENCRYPTION_KEY"}
	for _, name := range denied {
		if err := c.Call(ipc.OpPut, ipc.PutReq{
			Scope: ipc.Scope{}, Name: name, Value: []byte("invented"),
		}, &ipc.PutResp{}); err == nil {
			t.Errorf("%s should be denied to an unattended caller", name)
		}
	}
	// Names the globs do not cover must still flow, or the gate costs more than
	// it saves and gets turned off.
	for _, name := range []string{"TEMP_TABLE", "SECRET_SAUCE_MODE", "MY_AWS"} {
		if err := c.Call(ipc.OpPut, ipc.PutReq{
			Scope: ipc.Scope{}, Name: name, Value: []byte("fine"),
		}, &ipc.PutResp{}); err != nil {
			t.Errorf("%s is not covered by the deny list and should be storable: %v", name, err)
		}
	}
}

// A malformed pattern must match nothing, not everything: a typo in a deny list
// that refused every write would look like byn being broken.
func TestMatchesDenyPattern(t *testing.T) {
	cases := []struct {
		patterns []string
		name     string
		want     bool
	}{
		{[]string{"*_SECRET"}, "STRIPE_SECRET", true},
		{[]string{"*_SECRET"}, "SECRET_MODE", false},
		{[]string{"AWS_*"}, "AWS_REGION", true},
		{[]string{"AWS_*"}, "MY_AWS_REGION", false},
		{[]string{"EXACT_NAME"}, "EXACT_NAME", true},
		{[]string{"EXACT_NAME"}, "EXACT_NAME_2", false},
		{[]string{"[unclosed"}, "anything", false},
		{[]string{"[unclosed", "AWS_*"}, "AWS_KEY", true}, // a bad entry must not disable the good ones
		{nil, "ANY", false},
	}
	for _, tc := range cases {
		if _, got := matchesDenyPattern(tc.patterns, tc.name); got != tc.want {
			t.Errorf("matchesDenyPattern(%v, %q) = %v, want %v", tc.patterns, tc.name, got, tc.want)
		}
	}
}

// The launch line is the one surface a caller sees on every run without asking,
// so it is where an invented value has to be named.
func TestExecReportsUnattendedValuesAtLaunch(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\", \"AGENT_MADE\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("set-by-a-person"))
	grantBynFile(t, c, byn, pw)
	lockVaultStore(t, d, "default")
	c.Session = nil

	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "AGENT_MADE", Value: []byte("invented"),
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"},
	})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if len(resp.UnattendedValues) != 1 || resp.UnattendedValues[0] != "AGENT_MADE" {
		t.Fatalf("unattended_values = %v, want [AGENT_MADE] — the launch must name it", resp.UnattendedValues)
	}
	// And the value a person set must not be flagged, or the warning becomes
	// noise and stops being read.
	if m := valueMap(resp.Values); m["SEED"] != "set-by-a-person" {
		t.Errorf("SEED = %q, want set-by-a-person", m["SEED"])
	}
}

// Create, then UPDATE, then wire it into .byn — the workflow byn exists to
// serve, and the one a live run caught it failing.
//
// A "has this been written since it was created?" check used to sit behind the
// authorship record as belt and braces. An author changing its own value moved
// the entry's updated_at and tripped it, so the caller lost the variable it had
// just created and was sent to ask a person for permission to read its own
// token. Revocation is the precise answer and already covers the case the check
// was guarding: someone else's write takes authorship away at the moment it
// happens.
func TestSelfAuthored_SurvivesTheAuthorsOwnUpdate(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)
	lockVaultStore(t, d, "default")
	c.Session = nil

	put := func(v string) {
		t.Helper()
		if err := c.Call(ipc.OpPut, ipc.PutReq{
			Scope: ipc.Scope{}, Name: "AGENT_TOKEN", Value: []byte(v),
		}, &ipc.PutResp{}); err != nil {
			t.Fatalf("put %q: %v", v, err)
		}
	}
	put("v1")
	put("v2") // the author changes its mind — must not cost it the variable

	rewriteByn(t, byn, "[scope]\n\n[exec]\nenv = [\"SEED\", \"AGENT_TOKEN\"]\nactions = [\"mytool run\"]\n")
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"},
	})
	if err != nil {
		t.Fatalf("a value the caller created AND updated must still be its own: %v", err)
	}
	if m := valueMap(resp.Values); m["AGENT_TOKEN"] != "v2" {
		t.Fatalf("AGENT_TOKEN = %q, want v2; values=%v", m["AGENT_TOKEN"], m)
	}

	// The guarantee it must not have cost: someone else's overwrite still takes
	// authorship away. A person doing that is present, so the vault is open —
	// writing with the vault key is what being authenticated buys.
	var ur ipc.VaultUnlockResp
	tok, uerr := c.CallAndCaptureSession(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ur, nil)
	if uerr != nil {
		t.Fatalf("unlock: %v", uerr)
	}
	c.Session = tok
	setShares := stubOrigin(t, true)
	setShares(false)
	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "AGENT_TOKEN", Value: []byte("theirs"), Password: pw,
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("stranger overwrite: %v", err)
	}
	setShares(true)
	c.Session = nil
	if _, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"},
	}); err == nil {
		t.Fatal("after someone else replaced the value, the caller must no longer treat it as its own")
	}
}

// The pre-flight must agree with the gate about DECIDED commands, not only
// about what the .byn pins.
//
// Both halves were wrong and both misled in the worse direction: an approved
// command was reported "not pinned", sending the caller to ask for something
// already granted — the approval fatigue the queue exists to prevent — and a
// refused one was reported as a pause, inviting a retry that cannot succeed.
func TestExecPreflightAgreesAboutDecidedCommands(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"pinned run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	preflight := func(argv ...string) ipc.ExecPreflightResp {
		t.Helper()
		var r ipc.ExecPreflightResp
		if err := c.Call(ipc.OpExecPreflight, ipc.ExecPreflightReq{Path: byn, Argv: argv}, &r); err != nil {
			t.Fatalf("preflight: %v", err)
		}
		return r
	}
	raise := func(argv ...string) string {
		t.Helper()
		_, _ = execFetch(t, c, ipc.ExecFetchReq{Path: byn, Command: strings.Join(argv, " "), Argv: argv})
		var list ipc.ApprovalListResp
		if err := c.Call(ipc.OpApprovalList, ipc.ApprovalListReq{Status: "pending"}, &list); err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list.Entries) == 0 {
			t.Fatal("expected a pending request")
		}
		return list.Entries[len(list.Entries)-1].ID
	}

	t.Run("approved command reads as would-run", func(t *testing.T) {
		id := raise("cleanup", "--all")
		if err := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
			ID: id, Approve: true, Password: pw,
		}, &ipc.ApprovalDecideResp{}); err != nil {
			t.Fatalf("approve: %v", err)
		}
		r := preflight("cleanup", "--all")
		if !r.Approved {
			t.Errorf("approved = false; the pre-flight would send the caller to ask for what it already has (reason %q)", r.Reason)
		}
		// And the gate agrees: it runs.
		if _, err := execFetch(t, c, ipc.ExecFetchReq{
			Path: byn, Command: "cleanup --all", Argv: []string{"cleanup", "--all"},
		}); err != nil {
			t.Fatalf("the gate refused a command the pre-flight called approved: %v", err)
		}
	})

	t.Run("denied command reads as a wall, not a pause", func(t *testing.T) {
		id := raise("purge", "--now")
		if err := c.Call(ipc.OpApprovalDecide, ipc.ApprovalDecideReq{
			ID: id, Approve: false, Reason: "wrong target",
		}, &ipc.ApprovalDecideResp{}); err != nil {
			t.Fatalf("deny: %v", err)
		}
		r := preflight("purge", "--now")
		if r.Reason != "denied" {
			t.Fatalf("reason = %q, want denied — a refusal reported as a pause invites a retry that cannot succeed", r.Reason)
		}
		if r.DeniedReason != "wrong target" {
			t.Errorf("denied_reason = %q, want the decider's words", r.DeniedReason)
		}
		if r.DeniedAt == 0 {
			t.Error("denied_at should say when")
		}
	})
}

// stripAuthoredKey rewrites a trust record's capability without the authored
// key, reproducing one granted before this release.
func stripAuthoredKey(t *testing.T, d *Daemon, pw []byte) {
	t.Helper()
	store, err := trust.Load(d.cfg.Dir)
	if err != nil {
		t.Fatalf("load trust: %v", err)
	}
	capKey, ckerr := vcrypto.DeriveCapKey(d.fpMACKey)
	if ckerr != nil {
		t.Fatalf("cap key: %v", ckerr)
	}
	e := d.lookupVault(vault.DefaultVaultName)
	if e == nil {
		t.Fatal("no default vault")
	}
	vkKey, derr := e.store.DeriveSubkey(trust.VKMACKeyInfo)
	if derr != nil {
		t.Fatalf("vk key: %v", derr)
	}
	for _, rec := range store.Records {
		if len(rec.ExecCapability) == 0 {
			continue
		}
		keys, oerr := vcrypto.OpenCapability(capKey, rec.ExecCapability)
		if oerr != nil {
			t.Fatalf("open capability: %v", oerr)
		}
		delete(keys, vault.CapAuthoredKeyName)
		blob, serr := vcrypto.SealCapability(capKey, keys)
		if serr != nil {
			t.Fatalf("re-seal: %v", serr)
		}
		rec.ExecCapability = blob
		rec.SetMACs(d.fpMACKey, vkKey)
		if _, perr := trust.Put(d.cfg.Dir, rec); perr != nil {
			t.Fatalf("write record: %v", perr)
		}
	}
}

// What actually happens when you upgrade without re-trusting.
//
// I told the agent using byn that a locked `byn put` "fails closed until you
// re-trust". It reported the opposite with an audit trace, and it was right —
// but not because the gate is missing. A capability acquires the authored key
// the first time byn records authorship while the vault is open, because that
// path re-seals it. So the pre-release record heals itself the moment anyone
// stores a value with the vault unlocked, and only a project where that has
// never happened still needs the re-trust.
//
// Both halves are asserted here, because the claim in the documentation is only
// as good as the behaviour underneath it.
func TestUpgrade_CapabilityHealsOnTheFirstUnlockedWrite(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)
	stripAuthoredKey(t, d, pw) // now it looks like a record from before this release

	// Half one: locked, nothing has healed it yet → refused.
	lockVaultStore(t, d, "default")
	held := c.Session
	c.Session = nil
	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "BEFORE_HEAL", Value: []byte("v"),
	}, &ipc.PutResp{}); err == nil {
		t.Fatal("a locked unattended write must be refused while the record carries no key byn may write with")
	}

	// Half two: one unattended write with the vault OPEN re-seals the
	// capability, and the locked path works from then on — no re-trust.
	c.Session = held
	var ur ipc.VaultUnlockResp
	tok, uerr := c.CallAndCaptureSession(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ur, nil)
	if uerr != nil {
		t.Fatalf("unlock: %v", uerr)
	}
	c.Session = tok
	putVarUnattended(t, c, ipc.Scope{}, "HEALS_IT", []byte("v"))

	lockVaultStore(t, d, "default")
	c.Session = nil
	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "AFTER_HEAL", Value: []byte("v"),
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("after an unattended write with the vault open, the locked path should work without a re-trust: %v", err)
	}
}

// A grant made by THIS build always carries the key that lets a locked daemon
// write for its scope — so the locked path works immediately, with no re-trust
// and no healing.
//
// This is the case I kept failing to state. Told that an unattended put had
// succeeded on a locked vault whose project I assumed predated the release, I
// twice invented a mechanism to explain it — first "your vault must have been
// open", then "an earlier write must have healed the grant" — instead of asking
// when the grant was made. It had been made that morning, by this build. There
// was nothing to explain.
//
// Three states, and the tests below cover all of them, because the difference
// decides what someone upgrading has to do:
//   - granted by this build      → works at once (here)
//   - granted by an older build  → refused until re-trust or a write with the
//     vault open re-seals it (the heal test)
func TestFreshGrant_CarriesTheWritableKey(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	// Straight from the grant to a locked write: nothing in between that could
	// have re-sealed anything.
	lockVaultStore(t, d, "default")
	c.Session = nil
	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "STRAIGHT_AFTER_GRANT", Value: []byte("v"),
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("a grant from this build must allow a locked unattended write immediately: %v", err)
	}
}

// An ATTENDED write re-seals the grant too, which is not obvious and has a
// consequence worth stating: an owner storing a value with the vault open is
// what gives that project's agents the locked path from then on.
func TestAttendedWriteAlsoReSealsTheGrant(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)
	stripAuthoredKey(t, d, pw) // as an older byn would have left it

	// A perfectly ordinary put by the owner, with a session, vault open.
	putVar(t, c, ipc.Scope{}, "OWNER_SET_THIS", []byte("v"))

	lockVaultStore(t, d, "default")
	c.Session = nil
	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "AFTER_OWNER_WRITE", Value: []byte("v"),
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("an owner's ordinary put should have re-sealed the grant: %v", err)
	}
}

// A caller may clear up after itself, and only that.
//
// The cost of not allowing it, measured by the agent using byn: every unattended
// run left an orphan only its owner could delete, and byn's own delete path
// could not undo byn's own mistake. The rule is theirs and it is drawn where the
// danger stops — a name no .byn declares cannot be injected, so removing it
// cannot take a value away from a running program.
func TestUnattendedDelete(t *testing.T) {
	setShares := stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"DECLARED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "DECLARED", []byte("someone relies on this"))
	putVar(t, c, ipc.Scope{}, "OWNERS", []byte("not the agent's"))
	grantBynFile(t, c, byn, pw)
	lockVaultStore(t, d, "default")
	c.Session = nil

	del := func(name string) error {
		return c.Call(ipc.OpDelete, ipc.DeleteReq{Scope: ipc.Scope{}, Name: name}, &ipc.DeleteResp{})
	}

	t.Run("its own scratch value, declared by nothing", func(t *testing.T) {
		if err := c.Call(ipc.OpPut, ipc.PutReq{
			Scope: ipc.Scope{}, Name: "SCRATCH", Value: []byte("v"),
		}, &ipc.PutResp{}); err != nil {
			t.Fatalf("put: %v", err)
		}
		if err := del("SCRATCH"); err != nil {
			t.Fatalf("a caller must be able to remove the scratch value it created: %v", err)
		}
	})

	t.Run("a value it created that a .byn DOES declare stays human-only", func(t *testing.T) {
		// Same shape as above, but the name is in [exec] env — something could
		// be running on it, so removing it is a person's decision.
		if err := c.Call(ipc.OpPut, ipc.PutReq{
			Scope: ipc.Scope{}, Name: "DECLARED2", Value: []byte("v"),
		}, &ipc.PutResp{}); err != nil {
			t.Fatalf("put: %v", err)
		}
		rewriteByn(t, byn, "[scope]\n\n[exec]\nenv = [\"DECLARED\", \"DECLARED2\"]\nactions = [\"mytool run\"]\n")
		cat := []byte(authzPW)
		grantBynFile(t, c, byn, cat) // the .byn now declares it
		c.Session = nil
		if err := del("DECLARED2"); err == nil {
			t.Fatal("a declared name must not be removable without a credential — something may be running on it")
		}
	})

	t.Run("a value it did not create", func(t *testing.T) {
		if err := del("OWNERS"); err == nil {
			t.Fatal("a caller must not remove a value it did not store")
		}
	})

	t.Run("another session's value", func(t *testing.T) {
		if err := c.Call(ipc.OpPut, ipc.PutReq{
			Scope: ipc.Scope{}, Name: "OTHERS_SCRATCH", Value: []byte("v"),
		}, &ipc.PutResp{}); err != nil {
			t.Fatalf("put: %v", err)
		}
		setShares(false) // a different agent now
		if err := del("OTHERS_SCRATCH"); err == nil {
			t.Fatal("one agent must not remove another's value")
		}
		setShares(true)
	})
}

// A wildcard scope declares every name, so nothing in it is deletable without a
// credential.
//
// Written because I told the agent using byn that this holds before I had
// tested it. Under `env = "*"` every value in the scope is something a program
// may receive, so "no .byn declares this name" is never true there — and the
// delete rule has to read it that way round, or a wildcard project would be the
// one place an agent could remove anything it had created.
func TestUnattendedDelete_WildcardScopeRefusesEverything(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = \"*\"\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("v"))
	grantBynFile(t, c, byn, pw)
	lockVaultStore(t, d, "default")
	c.Session = nil

	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "SCRATCH", Value: []byte("v"),
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := c.Call(ipc.OpDelete, ipc.DeleteReq{
		Scope: ipc.Scope{}, Name: "SCRATCH",
	}, &ipc.DeleteResp{}); err == nil {
		t.Fatal("a wildcard grant declares every name; nothing under it may be deleted without a credential")
	}
}

// A value no .byn declares must never reach a child — the property the whole
// per-project allowlist exists for.
//
// R5-1, found by running byn in a ten-.byn monorepo. Values stored unattended
// were injected into EVERY exec in the scope, past each .byn's own list: one
// service received a value another service's agent had invented, and anything
// able to store a value unattended could put a name of its choosing into every
// byn-run process in the project. The cause was reading a nil allowlist as "no
// restriction" when it also means "this record has not been reconciled".
//
// Two .byn files sharing one scope, as a monorepo has, because with a single
// .byn the bug is invisible: everything in scope is declared by the only file
// there is.
func TestUnattendedValueObeysEachBynAllowlist(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Same scope, different declarations — the shape of a monorepo.
	mine := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"MINE\"]\nactions = [\"mytool run\"]\n")
	theirs := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"THEIRS\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "MINE", []byte("mine-val"))
	putVar(t, c, ipc.Scope{}, "THEIRS", []byte("theirs-val"))
	grantBynFile(t, c, mine, pw)
	grantBynFile(t, c, theirs, pw)

	lockVaultStore(t, d, "default")
	c.Session = nil

	// A value declared by NEITHER file.
	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "DECLARED_NOWHERE", Value: []byte("leak-probe"),
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	for _, tc := range []struct {
		name, byn, wants string
	}{
		{"first project", mine, "MINE"},
		{"second project", theirs, "THEIRS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := execFetch(t, c, ipc.ExecFetchReq{
				Path: tc.byn, Command: "mytool run", Argv: []string{"mytool", "run"},
			})
			if err != nil {
				t.Fatalf("exec: %v", err)
			}
			m := valueMap(resp.Values)
			if _, leaked := m["DECLARED_NOWHERE"]; leaked {
				t.Errorf("a value no .byn declares reached the child; injected: %v", keysOf(m))
			}
			if m[tc.wants] == "" {
				t.Errorf("the value this .byn DOES declare was not injected; injected: %v", keysOf(m))
			}
			// And it must not receive the other project's variable either.
			other := "THEIRS"
			if tc.wants == "THEIRS" {
				other = "MINE"
			}
			if _, crossed := m[other]; crossed {
				t.Errorf("%s received %s, which its .byn does not declare", tc.name, other)
			}
		})
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The pre-flight's unattended_env must equal what the launch actually injects.
//
// Part of R5-1: --dry-run reported no unattended value for the very command that
// then injected one, and doctor said "nothing injects them" about a value that
// was reaching every child. Diagnostics that disagree with the thing they
// describe are worse than none, because they are believed.
func TestPreflightUnattendedMatchesWhatIsInjected(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"DECLARED\"]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)
	lockVaultStore(t, d, "default")
	c.Session = nil

	// One declared, one not. Only the declared one may appear anywhere.
	for _, n := range []string{"DECLARED", "NOT_DECLARED"} {
		if err := c.Call(ipc.OpPut, ipc.PutReq{
			Scope: ipc.Scope{}, Name: n, Value: []byte("v"),
		}, &ipc.PutResp{}); err != nil {
			t.Fatalf("put %s: %v", n, err)
		}
	}

	var pre ipc.ExecPreflightResp
	if err := c.Call(ipc.OpExecPreflight, ipc.ExecPreflightReq{
		Path: byn, Argv: []string{"mytool", "run"},
	}, &pre); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"},
	})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}

	injected := valueMap(resp.Values)
	if _, leaked := injected["NOT_DECLARED"]; leaked {
		t.Fatalf("undeclared value injected: %v", keysOf(injected))
	}
	sort.Strings(pre.UnattendedEnv)
	if len(pre.UnattendedEnv) != 1 || pre.UnattendedEnv[0] != "DECLARED" {
		t.Fatalf("unattended_env = %v, want [DECLARED] — the pre-flight must name exactly what the launch injects",
			pre.UnattendedEnv)
	}
	// Every name the pre-flight calls unattended must actually arrive.
	for _, n := range pre.UnattendedEnv {
		if _, ok := injected[n]; !ok {
			t.Errorf("pre-flight promised %s and the launch did not inject it", n)
		}
	}
}
