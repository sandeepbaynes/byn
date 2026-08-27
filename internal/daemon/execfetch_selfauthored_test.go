package daemon

import (
	"os"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

// A variable the caller created itself is not a secret being disclosed to it.
// These cover the line between that and a genuine widening.

// stubOrigin pins the process-identity lookups so a single test process can act
// as one consistent agent. The lookups themselves are covered against the real
// process tree in procorigin_test.go.
func stubOrigin(t *testing.T, shares bool) {
	t.Helper()
	origCaller, origShares := callerOriginFn, sharesOriginFn
	t.Cleanup(func() { callerOriginFn, sharesOriginFn = origCaller, origShares })
	callerOriginFn = func(int) procRef { return procRef{PID: 4242, Start: 99} }
	sharesOriginFn = func(int, procRef) bool { return shares }
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
	store, err := trust.Load(d.cfg.Dir)
	if err != nil {
		t.Fatalf("load trust store: %v", err)
	}
	var out []string
	for _, rec := range store.Records {
		for _, a := range rec.SelfAuthored {
			out = append(out, a.Name)
		}
	}
	return out
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
	stubOrigin(t, true)
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	// The agent's own loop: create the value, then declare it.
	putVar(t, c, ipc.Scope{}, "API_TOKEN", []byte("tok-agent-made"))
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
	stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Created BEFORE the grant — the case authorship must never cover.
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	putVar(t, c, ipc.Scope{}, "AWS_SECRET", []byte("pre-existing"))
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	rewriteByn(t, byn, "[scope]\n\n[exec]\nenv = [\"SEED\", \"AWS_SECRET\"]\nactions = [\"mytool run\"]\n")

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"},
	})
	if code := errCode(t, err); code != ipc.CodeApprovalPending {
		t.Fatalf("code = %v, want approval_pending — a secret that predates the grant is a real widening", code)
	}
	// And for the right reason: byn never recorded authorship, because there
	// was no trusted .byn to record it against when the value was created.
	if names := authoredNames(t, d); hasAuthored(names, "AWS_SECRET") {
		t.Errorf("AWS_SECRET must not be recorded as self-authored; authored=%v", names)
	}
}

// An overwrite is authorization-gated because it may install a value the
// original author never saw. Authorship must not survive one.
func TestSelfAuthored_OverwrittenValueStillNeedsApproval(t *testing.T) {
	stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	putVar(t, c, ipc.Scope{}, "SHARED", []byte("agent-placeholder"))
	if names := authoredNames(t, d); !hasAuthored(names, "SHARED") {
		t.Fatalf("precondition: creating SHARED should record authorship; authored=%v", names)
	}
	// Someone with the password replaces it — now the author's claim to know
	// the stored value no longer holds.
	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{}, Name: "SHARED", Value: []byte("real-production-key"), Password: pw,
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
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
	stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	putVar(t, c, ipc.Scope{}, "TEMP", []byte("scratch"))
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
	stubOrigin(t, false) // records authorship, but this caller is a stranger
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	putVar(t, c, ipc.Scope{}, "OTHERS_VAR", []byte("not-yours"))
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
	stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	putVar(t, c, ipc.Scope{}, "SEED", []byte("seed-val"))
	grantBynFile(t, c, byn, pw)

	putVar(t, c, ipc.Scope{}, "API_TOKEN", []byte("tok-agent-made"))
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
