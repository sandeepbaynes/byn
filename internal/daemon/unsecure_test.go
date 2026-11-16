package daemon

import (
	"database/sql"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// putUnsecure stores a value unsealed, the way `byn put --unsecure` does.
func putUnsecure(t *testing.T, c *ipc.Client, scope ipc.Scope, name, value string) ipc.PutResp {
	t.Helper()
	var resp ipc.PutResp
	if err := c.Call(ipc.OpPut, ipc.PutReq{Scope: scope, Name: name, Value: []byte(value), Unsecure: true}, &resp); err != nil {
		t.Fatalf("put --unsecure %s: %v", name, err)
	}
	return resp
}

// asStranger runs fn over the connection with no session: a caller with no
// credential of any kind, which is what an agent is.
func asStranger(c *ipc.Client, fn func()) {
	held := c.Session
	c.Session = nil
	defer func() { c.Session = held }()
	fn()
}

func getVar(c *ipc.Client, name string) (ipc.GetResp, error) {
	var resp ipc.GetResp
	err := c.Call(ipc.OpGet, ipc.GetReq{Name: name}, &resp)
	return resp, err
}

func secureSet(c *ipc.Client, secure bool, pw []byte, names ...string) (ipc.SecureSetResp, error) {
	var resp ipc.SecureSetResp
	err := c.Call(ipc.OpSecureSet, ipc.SecureSetReq{Names: names, Secure: secure, Password: pw}, &resp)
	return resp, err
}

// The point of the feature: an unsecure value is read with the vault locked and
// no credential, and a sealed one beside it is not.
func TestUnsecure_GetNeedsNothing(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	putUnsecure(t, c, ipc.Scope{}, "PORT", "8080")
	putVar(t, c, ipc.Scope{}, "API_KEY", []byte("s3cret"))
	lockVaultStore(t, d, "default")

	asStranger(c, func() {
		got, err := getVar(c, "PORT")
		if err != nil {
			t.Fatalf("get of an unsecure value, locked, no credential: %v", err)
		}
		if string(got.Value) != "8080" || !got.Unsecure {
			t.Fatalf("PORT = %q unsecure=%v", got.Value, got.Unsecure)
		}
		if _, err := getVar(c, "API_KEY"); err == nil {
			t.Fatal("a sealed value was readable with no credential")
		}
	})
}

// A .byn's [auth] get = "always" does not put a gate back on a value its owner
// made unsecure.
func TestUnsecure_GetIgnoresAuthAlways(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putUnsecure(t, c, ipc.Scope{}, "REGION", "eu-west-1")
	byn := writeBynContent(t, "[scope]\n\n[auth]\nget = \"always\"\n")
	grantBynFile(t, c, byn, pw)

	got, err := getVar(c, "REGION")
	if err != nil || string(got.Value) != "eu-west-1" {
		t.Fatalf("get = %q, %v", got.Value, err)
	}
}

// Unsecure never carries over: a put that does not say so seals the value, even
// over an entry that was unsecure, and says that it did.
func TestUnsecure_PutIsNotSticky(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	if r := putUnsecure(t, c, ipc.Scope{}, "TOKEN", "placeholder"); !r.Unsecure || r.Resecured {
		t.Fatalf("first put: %+v", r)
	}
	var r ipc.PutResp
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "TOKEN", Value: []byte("the-real-one")}, &r); err != nil {
		t.Fatalf("plain put over an unsecure entry: %v", err)
	}
	if r.Unsecure || !r.Resecured {
		t.Fatalf("plain put over an unsecure entry: %+v, want Resecured", r)
	}
	asStranger(c, func() {
		if _, err := getVar(c, "TOKEN"); err == nil {
			t.Fatal("the real value is readable with no credential: unsecure was inherited")
		}
	})
}

// An unsecure value carries a MAC, so writing one takes a key just as a sealed
// write does: on a locked vault with no grant covering the scope there is
// none, and the write is refused the way a sealed one is. The master password
// supplies it without unlocking anything.
func TestUnsecure_LockedWriteNeedsAKey(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	stubOrigin(t, true)
	lockVaultStore(t, d, "default")

	asStranger(c, func() {
		err := c.Call(ipc.OpPut, ipc.PutReq{Name: "FEATURE_X", Value: []byte("on"), Unsecure: true}, &ipc.PutResp{})
		if code := errCode(t, err); code != ipc.CodeAuthRequired {
			t.Fatalf("locked, no grant: code = %v, want auth_required", code)
		}
		var r ipc.PutResp
		if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "FEATURE_X", Value: []byte("on"), Unsecure: true,
			Password: []byte(authzPW)}, &r); err != nil {
			t.Fatalf("locked, with the password: %v", err)
		}
		if !r.Created || !r.Unsecure {
			t.Fatalf("put: %+v, want created and unsecure", r)
		}
		if got, err := getVar(c, "FEATURE_X"); err != nil || string(got.Value) != "on" {
			t.Fatalf("get = %q, %v", got.Value, err)
		}
	})
	if !d.lookupVault("default").store.IsLocked() {
		t.Fatal("a password-backed write unlocked the vault")
	}
}

// rewriteStoredValue changes a row in the vault file the way something other
// than byn would: straight into the database, keeping whatever header is there.
func rewriteStoredValue(t *testing.T, d *Daemon, name, value string) {
	t.Helper()
	var path string
	_ = filepath.WalkDir(d.cfg.Dir, func(p string, e fs.DirEntry, err error) error {
		if err == nil && e.Name() == "vault.db" && path == "" {
			path = p
		}
		return nil
	})
	if path == "" {
		t.Fatalf("no vault.db under %s", d.cfg.Dir)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var blob []byte
	if err := db.QueryRow(`SELECT value FROM entries WHERE name=?`, name).Scan(&blob); err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	const header = 33
	if len(blob) < header {
		t.Fatalf("%s: stored blob is %d bytes, shorter than its header", name, len(blob))
	}
	if _, err := db.Exec(`UPDATE entries SET value=? WHERE name=?`,
		append(append([]byte{}, blob[:header]...), value...), name); err != nil {
		t.Fatalf("rewrite %s: %v", name, err)
	}
}

// A trusted run is the one that carries secrets, so it is the one where a
// rewritten unsecure value would do harm — and a locked daemon checks it with
// the grant's own key. The run is refused, by name; nothing is quietly dropped.
func TestExec_TrustedRunRefusesATamperedUnsecureValue(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "DB_URL", []byte("postgres://prod"))
	putUnsecure(t, c, ipc.Scope{}, "API_URL", "https://api.example")
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"DB_URL\", \"API_URL\"]\nactions = [\"srv run\"]\n")
	grantBynFile(t, c, byn, pw)
	lockVaultStore(t, d, "default")
	req := ipc.ExecFetchReq{Path: byn, Command: "srv run", Argv: []string{"srv", "run"}}

	if _, err := execFetch(t, c, req); err != nil {
		t.Fatalf("before tampering: %v", err)
	}
	rewriteStoredValue(t, d, "API_URL", "https://evil.example")
	_, err := execFetch(t, c, req)
	if code := errCode(t, err); code != ipc.CodeTampered {
		t.Fatalf("after tampering: code = %v (%v), want value_tampered", code, err)
	}
	if !strings.Contains(err.Error(), "API_URL") {
		t.Fatalf("the refusal does not name the value: %v", err)
	}
	// The same grant lets a plain read be checked too, locked as the vault is.
	if _, err := getVar(c, "API_URL"); errCode(t, err) != ipc.CodeTampered {
		t.Fatalf("locked get with a grant for the scope: %v, want value_tampered", err)
	}
}

// With the vault locked and no grant for the scope there is no key to check
// with, and the value is returned as it stands. This is the documented limit,
// pinned so that it changes on purpose or not at all.
func TestUnsecure_LockedReadWithNoGrantIsUnchecked(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	putUnsecure(t, c, ipc.Scope{}, "API_URL", "https://api.example")
	rewriteStoredValue(t, d, "API_URL", "https://evil.example")
	lockVaultStore(t, d, "default")
	if got, err := getVar(c, "API_URL"); err != nil || string(got.Value) != "https://evil.example" {
		t.Fatalf("locked, no grant: %q, %v", got.Value, err)
	}
}

// byn get on an open vault checks too, and says what to do.
func TestUnsecure_GetRefusesATamperedValue(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	putUnsecure(t, c, ipc.Scope{}, "API_URL", "https://api.example")
	rewriteStoredValue(t, d, "API_URL", "https://evil.example")

	_, err := getVar(c, "API_URL")
	if code := errCode(t, err); code != ipc.CodeTampered {
		t.Fatalf("code = %v (%v), want value_tampered", code, err)
	}
	// Setting it again is the repair.
	putUnsecure(t, c, ipc.Scope{}, "API_URL", "https://api.example")
	if got, err := getVar(c, "API_URL"); err != nil || string(got.Value) != "https://api.example" {
		t.Fatalf("after repair: %q, %v", got.Value, err)
	}
}

// Replacing someone else's value is still an update, unsecure or not.
func TestUnsecure_OverwriteStillGated(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	putVar(t, c, ipc.Scope{}, "DB_URL", []byte("postgres://prod"))

	asStranger(c, func() {
		err := c.Call(ipc.OpPut, ipc.PutReq{Name: "DB_URL", Value: []byte("postgres://evil"), Unsecure: true}, &ipc.PutResp{})
		if code := errCode(t, err); code != ipc.CodeAuthRequired {
			t.Fatalf("code = %v, want auth_required", code)
		}
	})
	if got, err := getVar(c, "DB_URL"); err != nil || string(got.Value) != "postgres://prod" || got.Unsecure {
		t.Fatalf("DB_URL = %q unsecure=%v err=%v", got.Value, got.Unsecure, err)
	}
}

// Making a stored value unsecure takes the password. A session — which is
// enough to READ the value — is not enough to publish it.
func TestSecureSet_UnsecureNeedsThePassword(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "LOG_LEVEL", []byte("debug"))

	_, err := secureSet(c, false, nil, "LOG_LEVEL")
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("with a session only: code = %v, want auth_required", code)
	}
	asStranger(c, func() {
		if _, err := getVar(c, "LOG_LEVEL"); err == nil {
			t.Fatal("value became readable although the change was refused")
		}
	})

	resp, err := secureSet(c, false, pw, "LOG_LEVEL")
	if err != nil || len(resp.Changed) != 1 {
		t.Fatalf("with the password: %+v, %v", resp, err)
	}
	asStranger(c, func() {
		if got, err := getVar(c, "LOG_LEVEL"); err != nil || string(got.Value) != "debug" {
			t.Fatalf("get after unsecure = %q, %v", got.Value, err)
		}
	})
}

// [auth] get = "none" frees reads in a scope. It must not free publishing.
func TestSecureSet_AuthNoneDoesNotRelaxIt(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "K", []byte("v"))
	byn := writeBynContent(t, "[scope]\n\n[auth]\nget = \"none\"\nupdate = \"none\"\n")
	grantBynFile(t, c, byn, pw)

	asStranger(c, func() {
		_, err := secureSet(c, false, nil, "K")
		if code := errCode(t, err); code != ipc.CodeAuthRequired {
			t.Fatalf("code = %v, want auth_required", code)
		}
	})
}

// Sealing a value takes access away, so a session is enough; and afterwards the
// value is gated again.
func TestSecureSet_SecureWithSession(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	putUnsecure(t, c, ipc.Scope{}, "A", "1")
	putUnsecure(t, c, ipc.Scope{}, "B", "2")

	asStranger(c, func() {
		_, err := secureSet(c, true, nil, "A")
		if code := errCode(t, err); code != ipc.CodeAuthRequired {
			t.Fatalf("no credential: code = %v, want auth_required", code)
		}
	})
	resp, err := secureSet(c, true, nil, "A", "B")
	if err != nil || len(resp.Changed) != 2 {
		t.Fatalf("secure: %+v, %v", resp, err)
	}
	asStranger(c, func() {
		if _, err := getVar(c, "A"); err == nil {
			t.Fatal("A is still readable with no credential after being secured")
		}
	})
	if got, err := getVar(c, "B"); err != nil || string(got.Value) != "2" || got.Unsecure {
		t.Fatalf("B = %q unsecure=%v err=%v", got.Value, got.Unsecure, err)
	}
}

// A locked vault can be changed on the password alone, and stays locked.
func TestSecureSet_LockedWithPassword(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "K", []byte("v"))
	lockVaultStore(t, d, "default")

	asStranger(c, func() {
		if _, err := secureSet(c, false, pw, "K"); err != nil {
			t.Fatalf("unsecure, locked, with password: %v", err)
		}
		if got, err := getVar(c, "K"); err != nil || string(got.Value) != "v" {
			t.Fatalf("get = %q, %v", got.Value, err)
		}
	})
	if !d.lookupVault("default").store.IsLocked() {
		t.Fatal("the vault was left unlocked")
	}
}

// One name that cannot be changed leaves every name as it was.
func TestSecureSet_AllOrNone(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "REAL", []byte("v"))

	_, err := secureSet(c, false, pw, "REAL", "NOPE")
	if code := errCode(t, err); code != ipc.CodeNotFound {
		t.Fatalf("code = %v, want not_found", code)
	}
	asStranger(c, func() {
		if _, err := getVar(c, "REAL"); err == nil {
			t.Fatal("REAL was made unsecure although the request failed")
		}
	})
}

func TestUnsecure_ListMarksThem(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	putUnsecure(t, c, ipc.Scope{}, "PLAIN", "")
	putVar(t, c, ipc.Scope{}, "SEALED", []byte("v"))
	lockVaultStore(t, d, "default")

	var resp ipc.ListResp
	if err := c.Call(ipc.OpList, ipc.ListReq{}, &resp); err != nil {
		t.Fatal(err)
	}
	for _, m := range resp.Secrets {
		switch m.Name {
		case "PLAIN":
			if !m.Unsecure || m.Empty == nil || !*m.Empty {
				t.Errorf("PLAIN: unsecure=%v empty=%v", m.Unsecure, m.Empty)
			}
		case "SEALED":
			if m.Unsecure || m.Empty != nil {
				t.Errorf("SEALED: unsecure=%v empty=%v (locked: emptiness must stay unknown)", m.Unsecure, m.Empty)
			}
		}
	}
}

// ---- exec -------------------------------------------------------------------

// An untrusted .byn no longer stops the command: it runs on the unsecure values
// the file asks for, the sealed ones are withheld by name, and the response
// says the file is not trusted.
func TestExec_UntrustedBynRunsOnUnsecureValues(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	putUnsecure(t, c, ipc.Scope{}, "PORT", "8080")
	putUnsecure(t, c, ipc.Scope{}, "NOT_ASKED_FOR", "x")
	putVar(t, c, ipc.Scope{}, "API_KEY", []byte("s3cret"))
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"PORT\", \"API_KEY\", \"NOWHERE\"]\n")
	lockVaultStore(t, d, "default")

	var resp ipc.ExecFetchResp
	var err error
	asStranger(c, func() {
		resp, err = execFetch(t, c, ipc.ExecFetchReq{Path: byn, Command: "make test", Argv: []string{"make", "test"}})
	})
	if err != nil {
		t.Fatalf("untrusted .byn with unsecure values: %v", err)
	}
	m := valueMap(resp.Values)
	if len(m) != 1 || m["PORT"] != "8080" {
		t.Fatalf("values = %v, want only PORT", m)
	}
	if resp.Untrusted == "" {
		t.Error("the response does not say the .byn is untrusted")
	}
	if len(resp.WithheldValues) != 1 || resp.WithheldValues[0] != "API_KEY" {
		t.Errorf("withheld = %v, want [API_KEY]", resp.WithheldValues)
	}
	if len(resp.MissingValues) != 1 || resp.MissingValues[0] != "NOWHERE" {
		t.Errorf("missing = %v, want [NOWHERE] (a sealed value is withheld, not missing)", resp.MissingValues)
	}
}

// A wildcard in an untrusted file is still only a selection among public
// values: every unsecure one, and no sealed one.
func TestExec_UntrustedWildcardGetsUnsecureOnly(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	putUnsecure(t, c, ipc.Scope{}, "A", "1")
	putUnsecure(t, c, ipc.Scope{}, "B", "2")
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s"))
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = \"*\"\nactions = \"*\"\n")

	resp, err := execFetch(t, c, ipc.ExecFetchReq{Path: byn, Command: "x", Argv: []string{"x"}})
	if err != nil {
		t.Fatal(err)
	}
	if m := valueMap(resp.Values); len(m) != 2 || m["SECRET"] != "" {
		t.Fatalf("values = %v, want A and B only", m)
	}
	if len(resp.WithheldValues) != 1 || resp.WithheldValues[0] != "SECRET" {
		t.Errorf("withheld = %v", resp.WithheldValues)
	}
}

// Such a run must be the caller's own. The paths that hand a run to the privsep
// helper answer with a redirect, never with a child running as another user on
// the strength of a file nobody approved.
func TestExec_UntrustedIsNeverSpawnedUnderPrivsep(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	putUnsecure(t, c, ipc.Scope{}, "PORT", "8080")
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"PORT\"]\n")
	d.execProvisioned.Store(true)

	err := c.Call(ipc.OpExecAuthorize, ipc.ExecAuthorizeReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: byn, Command: "true", Argv: []string{"true"}},
		AbsTarget:    "/usr/bin/true",
	}, &ipc.ExecAuthorizeResp{})
	if code := errCode(t, err); code != ipc.CodeUnsecureOnly {
		t.Fatalf("exec.authorize code = %v, want unsecure_only", code)
	}
}

// An alias is defined by the trust record. Without trust there is no command.
func TestExec_UntrustedAliasStillRefused(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	putUnsecure(t, c, ipc.Scope{}, "PORT", "8080")
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"PORT\"]\n\n[aliases]\ngo = \"make test\"\n")

	_, err := execFetch(t, c, ipc.ExecFetchReq{Path: byn, Alias: "go", Command: "alias go"})
	if code := errCode(t, err); code != ipc.CodeTrustDenied {
		t.Fatalf("code = %v, want trust_denied", code)
	}
}

// A trusted .byn that grows by an unsecure name is not asking for more: it
// runs, with the new value, and nothing is queued. Seal that value and the same
// file is asking for more after all.
func TestExec_AddingAnUnsecureNameIsNotAWidening(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "DB_URL", []byte("postgres://prod"))
	putUnsecure(t, c, ipc.Scope{}, "PORT", "8080")
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"DB_URL\"]\nactions = [\"srv run\"]\n")
	grantBynFile(t, c, byn, pw)
	rewriteByn(t, byn, "[scope]\n\n[exec]\nenv = [\"DB_URL\", \"PORT\"]\nactions = [\"srv run\"]\n")
	lockVaultStore(t, d, "default")

	req := ipc.ExecFetchReq{Path: byn, Command: "srv run", Argv: []string{"srv", "run"}}
	var resp ipc.ExecFetchResp
	var err error
	asStranger(c, func() { resp, err = execFetch(t, c, req) })
	if err != nil {
		t.Fatalf("adding an unsecure name to a trusted .byn: %v", err)
	}
	m := valueMap(resp.Values)
	if m["DB_URL"] != "postgres://prod" || m["PORT"] != "8080" {
		t.Fatalf("values = %v, want both", m)
	}
	if resp.Untrusted != "" {
		t.Errorf("a trusted run was reported as untrusted: %q", resp.Untrusted)
	}

	// Seal PORT. The grant never covered it, so now the file asks for more.
	if _, err := secureSet(c, true, pw, "PORT"); err != nil {
		t.Fatalf("secure PORT: %v", err)
	}
	asStranger(c, func() { _, err = execFetch(t, c, req) })
	if code := errCode(t, err); code != ipc.CodeApprovalPending {
		t.Fatalf("after sealing PORT: code = %v, want approval_pending", code)
	}
}

// A trusted run injects unsecure and sealed values side by side, locked.
func TestExec_TrustedRunMixesBoth(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "DB_URL", []byte("postgres://prod"))
	putUnsecure(t, c, ipc.Scope{}, "PORT", "8080")
	putUnsecure(t, c, ipc.Scope{}, "OTHER", "not-listed")
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"DB_URL\", \"PORT\"]\nactions = [\"srv run\"]\n")
	grantBynFile(t, c, byn, pw)
	lockVaultStore(t, d, "default")

	resp, err := execFetch(t, c, ipc.ExecFetchReq{Path: byn, Command: "srv run", Argv: []string{"srv", "run"}})
	if err != nil {
		t.Fatal(err)
	}
	m := valueMap(resp.Values)
	if len(m) != 2 || m["DB_URL"] != "postgres://prod" || m["PORT"] != "8080" {
		t.Fatalf("values = %v, want DB_URL and PORT only", m)
	}
}

// --unsecure with no .byn: the scope's unsecure values, no credential, locked.
func TestExec_UnsecureOnlyNoByn(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	putUnsecure(t, c, ipc.Scope{}, "PORT", "8080")
	putVar(t, c, ipc.Scope{}, "API_KEY", []byte("s3cret"))
	lockVaultStore(t, d, "default")

	var resp ipc.ExecFetchResp
	var err error
	asStranger(c, func() {
		resp, err = execFetch(t, c, ipc.ExecFetchReq{UnsecureOnly: true, Command: "env", Argv: []string{"env"}})
	})
	if err != nil {
		t.Fatal(err)
	}
	if m := valueMap(resp.Values); len(m) != 1 || m["PORT"] != "8080" {
		t.Fatalf("values = %v, want only PORT", m)
	}
	if !resp.UnsecureOnly || resp.Untrusted != "" {
		t.Errorf("UnsecureOnly=%v Untrusted=%q", resp.UnsecureOnly, resp.Untrusted)
	}
}
