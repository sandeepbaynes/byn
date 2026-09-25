package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

// The field report these reproduce: a service's prod env silently ran without
// a variable that `byn ls` listed and `byn get` returned, because the value
// lived in default and had been stored unattended — sealed under default's
// authored key, which a prod grant did not carry. Overriding it in prod made
// it appear; reverting made it vanish again.

// prodScope is what the CLI sends for a .byn scoped to prod: it resolves the
// scope from the file, and the daemon decrypts in that scope.
var prodScope = ipc.Scope{Env: "prod"}

const (
	prodWildcardByn = "[scope]\nenv = \"prod\"\n\n[exec]\nenv = \"*\"\nactions = [\"mytool run\"]\n"
	defaultByn      = "[scope]\n\n[exec]\nenv = \"*\"\nactions = [\"mytool run\"]\n"
)

// inheritFixture: default + prod envs, a trusted .byn for each, the vault
// locked, and AUTH_KEY stored in default by an agent (unattended).
func inheritFixture(t *testing.T, prodByn string) (*Daemon, *ipc.Client, string) {
	t.Helper()
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "prod"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatalf("create prod: %v", err)
	}
	putVar(t, c, ipc.Scope{}, "SEED", []byte("owner-set"))

	grantBynFile(t, c, writeBynContent(t, defaultByn), pw)
	prod := writeBynContent(t, prodByn)
	grantBynFile(t, c, prod, pw)

	lockVaultStore(t, d, "default")
	putVarUnattended(t, c, ipc.Scope{}, "AUTH_KEY", []byte("agent-made"))
	c.Session = nil
	return d, c, prod
}

func mustBeAuthoredRow(t *testing.T, d *Daemon, env, name string, want bool) {
	t.Helper()
	st := d.vaults["default"].store
	_, unatt, found, err := st.EntryOrigin(context.Background(), vault.Scope{Project: "default", Env: env}, name)
	if err != nil || !found {
		t.Fatalf("EntryOrigin(%s/%s): found=%v err=%v", env, name, found, err)
	}
	if unatt != want {
		t.Fatalf("%s/%s unattended = %v, want %v", env, name, unatt, want)
	}
}

func TestInheritedUnattended_WildcardProdGrantInjectsWhileLocked(t *testing.T) {
	d, c, prod := inheritFixture(t, prodWildcardByn)
	mustBeAuthoredRow(t, d, "default", "AUTH_KEY", true)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{Path: prod, Scope: prodScope, Command: "mytool run", Argv: []string{"mytool", "run"}})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	m := valueMap(resp.Values)
	if m["AUTH_KEY"] != "agent-made" {
		t.Fatalf("AUTH_KEY = %q, want agent-made — an inherited unattended value must reach prod; values=%v", m["AUTH_KEY"], m)
	}
	if m["SEED"] != "owner-set" {
		t.Fatalf("SEED = %q, want owner-set (inherited owner value, vault locked)", m["SEED"])
	}
	if len(resp.MissingValues) != 0 {
		t.Fatalf("missing = %v, want none", resp.MissingValues)
	}
	// Provenance travels with an inherited value too.
	if strings.Join(resp.UnattendedValues, ",") != "AUTH_KEY" {
		t.Fatalf("unattended_values = %v, want [AUTH_KEY]", resp.UnattendedValues)
	}
}

func TestInheritedUnattended_ExplicitProdGrantInjectsWhileLocked(t *testing.T) {
	_, c, prod := inheritFixture(t,
		"[scope]\nenv = \"prod\"\n\n[exec]\nenv = [\"SEED\", \"AUTH_KEY\"]\nactions = [\"mytool run\"]\n")
	resp, err := execFetch(t, c, ipc.ExecFetchReq{Path: prod, Scope: prodScope, Command: "mytool run", Argv: []string{"mytool", "run"}})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if m := valueMap(resp.Values); m["AUTH_KEY"] != "agent-made" || m["SEED"] != "owner-set" {
		t.Fatalf("values = %v, want AUTH_KEY and SEED", m)
	}
}

// Carrying default's keys must not widen what a .byn receives: its own list
// still decides.
func TestInheritedUnattended_AllowlistStillFilters(t *testing.T) {
	_, c, prod := inheritFixture(t,
		"[scope]\nenv = \"prod\"\n\n[exec]\nenv = [\"SEED\"]\nactions = [\"mytool run\"]\n")
	resp, err := execFetch(t, c, ipc.ExecFetchReq{Path: prod, Scope: prodScope, Command: "mytool run", Argv: []string{"mytool", "run"}})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if _, leaked := valueMap(resp.Values)["AUTH_KEY"]; leaked {
		t.Fatal("AUTH_KEY injected into a .byn that does not declare it")
	}
}

// A grant sealed before byn carried default's keys cannot open the value. It
// must say so, by name and with the fix — never drop it silently.
func TestInheritedUnattended_OldGrantIsReportedNotSilent(t *testing.T) {
	d, _, _ := inheritFixture(t, prodWildcardByn)
	ctx := context.Background()
	st := d.vaults["default"].store
	scope := vault.Scope{Project: "default", Env: "prod"}

	store, err := trust.Load(d.cfg.Dir)
	if err != nil {
		t.Fatal(err)
	}
	var rec trust.Record
	for _, r := range store.Records {
		if r.ScopeEnv == "prod" {
			rec = r
		}
	}
	if len(rec.ExecCapability) == 0 {
		t.Fatal("prod grant has no capability")
	}
	capKey, err := vcrypto.DeriveCapKey(d.fpMACKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := vcrypto.OpenCapability(capKey, rec.ExecCapability)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys[vault.CapDefaultAuthoredKeyName]) == 0 || len(keys[vault.CapDefaultScopeKeyName]) == 0 {
		t.Fatal("a wildcard prod grant must carry default's authored and scope keys")
	}
	// Strip them: what a grant from before this change holds.
	delete(keys, vault.CapDefaultAuthoredKeyName)
	delete(keys, vault.CapDefaultScopeKeyName)
	rec.ExecCapability, err = vcrypto.SealCapability(capKey, keys)
	if err != nil {
		t.Fatal(err)
	}

	values, le := d.execValuesFromCapability(ctx, "t", st, scope, rec)
	if le != nil {
		t.Fatalf("exec values: %v", le.Err)
	}
	if _, got := valueMap(values)["AUTH_KEY"]; got {
		t.Fatal("precondition: an old grant should not open the inherited unattended value")
	}
	missing := d.splitUnreachable(ctx, st, scope, d.wildcardNotDelivered(ctx, st, scope, nil, values))
	if len(missing) != 1 || !strings.HasPrefix(missing[0], "AUTH_KEY") ||
		!strings.Contains(missing[0], "byn import --unattended --env default") {
		t.Fatalf("missing = %v, want AUTH_KEY with the import fix", missing)
	}
}

func TestList_MarksInheritedUnattended(t *testing.T) {
	_, c, _ := inheritFixture(t, prodWildcardByn)
	var resp ipc.ListResp
	if err := c.Call(ipc.OpList, ipc.ListReq{Scope: ipc.Scope{Env: "prod"}}, &resp); err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, s := range resp.Secrets {
		switch s.Name {
		case "AUTH_KEY":
			if !s.Unattended || !s.UnattendedInherited {
				t.Fatalf("AUTH_KEY in prod: unattended=%v inherited=%v, want both", s.Unattended, s.UnattendedInherited)
			}
		case "SEED":
			if s.Unattended {
				t.Fatal("SEED was set by the owner and must not be marked")
			}
		}
	}
}

func TestUnattendedList_NamesEveryScopeWhileLocked(t *testing.T) {
	_, c, _ := inheritFixture(t, prodWildcardByn)
	var resp ipc.UnattendedListResp
	if err := c.Call(ipc.OpUnattendedList, ipc.UnattendedListReq{}, &resp); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.Items) != 1 || resp.Items[0] != (ipc.UnattendedItem{Project: "default", Env: "default", Name: "AUTH_KEY"}) {
		t.Fatalf("items = %+v, want default/default AUTH_KEY", resp.Items)
	}
}

func TestDoctor_WarnsAboutUnattendedValues(t *testing.T) {
	_, c, _ := inheritFixture(t, prodWildcardByn)
	var resp ipc.DoctorResp
	if err := c.Call(ipc.OpDoctor, ipc.DoctorReq{}, &resp); err != nil {
		t.Fatalf("doctor: %v", err)
	}
	for _, ch := range resp.Checks {
		if ch.Name != "vault[default].unattended" {
			continue
		}
		if ch.Severity != "warn" || !strings.Contains(ch.Detail, "default/default AUTH_KEY") ||
			!strings.Contains(ch.Detail, "byn import --unattended --all --vault default") {
			t.Fatalf("check = %+v", ch)
		}
		return
	}
	t.Fatal("doctor has no unattended check for the default vault")
}

func TestUnattendedImport_DryRunNeedsNoCredentialAndChangesNothing(t *testing.T) {
	d, c, _ := inheritFixture(t, prodWildcardByn)
	var resp ipc.UnattendedImportResp
	if err := c.Call(ipc.OpUnattendedImport, ipc.UnattendedImportReq{DryRun: true}, &resp); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(resp.Imported) != 1 || resp.Imported[0].Name != "AUTH_KEY" {
		t.Fatalf("imported = %+v", resp.Imported)
	}
	mustBeAuthoredRow(t, d, "default", "AUTH_KEY", true)
}

func TestUnattendedImport_RefusedWithoutCredential(t *testing.T) {
	d, c, _ := inheritFixture(t, prodWildcardByn)
	err := c.Call(ipc.OpUnattendedImport, ipc.UnattendedImportReq{}, &ipc.UnattendedImportResp{})
	if err == nil {
		t.Fatal("an agent must not be able to adopt values on the owner's behalf with no credential")
	}
	mustBeAuthoredRow(t, d, "default", "AUTH_KEY", true)
}

func TestUnattendedImport_SealsForgetsAuthorshipAndKeepsProdWorking(t *testing.T) {
	d, c, prod := inheritFixture(t, prodWildcardByn)
	var resp ipc.UnattendedImportResp
	if err := c.Call(ipc.OpUnattendedImport, ipc.UnattendedImportReq{Password: []byte(authzPW)}, &resp); err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(resp.Imported) != 1 || resp.Imported[0].Name != "AUTH_KEY" {
		t.Fatalf("imported = %+v", resp.Imported)
	}
	mustBeAuthoredRow(t, d, "default", "AUTH_KEY", false)
	if !d.vaults["default"].store.IsLocked() {
		t.Fatal("import must not leave the vault unlocked")
	}
	if hasAuthored(authoredNames(t, d), "AUTH_KEY") {
		t.Fatal("the agent must lose authorship of a value the owner adopted")
	}
	// Still locked: prod's grant was re-sealed with the key that opens the
	// re-sealed row.
	fetched, err := execFetch(t, c, ipc.ExecFetchReq{Path: prod, Scope: prodScope, Command: "mytool run", Argv: []string{"mytool", "run"}})
	if err != nil {
		t.Fatalf("exec after import: %v", err)
	}
	if m := valueMap(fetched.Values); m["AUTH_KEY"] != "agent-made" {
		t.Fatalf("AUTH_KEY after import = %q, want agent-made; values=%v", m["AUTH_KEY"], m)
	}
	if len(fetched.UnattendedValues) != 0 {
		t.Fatalf("an imported value is no longer unattended: %v", fetched.UnattendedValues)
	}
	var again ipc.UnattendedListResp
	if err := c.Call(ipc.OpUnattendedList, ipc.UnattendedListReq{}, &again); err != nil || len(again.Items) != 0 {
		t.Fatalf("after import: items=%v err=%v", again.Items, err)
	}
}

func TestUnattendedImport_NamedInheritedPointsAtDefault(t *testing.T) {
	_, c, _ := inheritFixture(t, prodWildcardByn)
	var resp ipc.UnattendedImportResp
	if err := c.Call(ipc.OpUnattendedImport, ipc.UnattendedImportReq{
		Scope: ipc.Scope{Env: "prod"}, Names: []string{"AUTH_KEY", "NOPE"}, DryRun: true,
	}, &resp); err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(resp.Imported) != 0 || len(resp.Skipped) != 2 {
		t.Fatalf("resp = %+v", resp)
	}
	if !strings.Contains(resp.Skipped[0].Reason, "--env default") {
		t.Fatalf("AUTH_KEY skip reason = %q, want a pointer to --env default", resp.Skipped[0].Reason)
	}
	if !strings.Contains(resp.Skipped[1].Reason, "not an unattended value") {
		t.Fatalf("NOPE skip reason = %q", resp.Skipped[1].Reason)
	}
}

// A session passes the authorization gate, but re-sealing still needs the
// vault key; a locked vault with no password must say how to supply it.
func TestUnattendedImport_LockedWithSessionButNoPasswordSaysUnlock(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	grantBynFile(t, c, writeBynContent(t, defaultByn), pw)
	session := c.Session
	lockVaultStore(t, d, "default")
	putVarUnattended(t, c, ipc.Scope{}, "AUTH_KEY", []byte("agent-made"))
	c.Session = session
	err := c.Call(ipc.OpUnattendedImport, ipc.UnattendedImportReq{}, &ipc.UnattendedImportResp{})
	if err == nil || !strings.Contains(err.Error(), "--password-stdin") {
		t.Fatalf("err = %v, want a locked refusal naming --password-stdin", err)
	}
	mustBeAuthoredRow(t, d, "default", "AUTH_KEY", true)
}

// An owner adding a value to default must reach a prod grant that declares it
// by name, with the vault later locked: the write re-seals the grants of every
// env that inherits from default, not only default's own.
func TestDefaultWrite_RefreshesInheritingExplicitGrants(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "prod"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatal(err)
	}
	grantBynFile(t, c, writeBynContent(t, defaultByn), pw)
	prod := writeBynContent(t, "[scope]\nenv = \"prod\"\n\n[exec]\nenv = [\"LATER\"]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, prod, pw)

	putVar(t, c, ipc.Scope{}, "LATER", []byte("added-after-grant"))
	lockVaultStore(t, d, "default")
	c.Session = nil

	resp, err := execFetch(t, c, ipc.ExecFetchReq{Path: prod, Scope: prodScope, Command: "mytool run", Argv: []string{"mytool", "run"}})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if m := valueMap(resp.Values); m["LATER"] != "added-after-grant" {
		t.Fatalf("LATER = %q; missing=%v", m["LATER"], resp.MissingValues)
	}
}

func TestRefreshScope(t *testing.T) {
	rec := trust.Record{Vault: "v", ScopeProject: "p", ScopeEnv: "prod"}
	if sc, ok := refreshScope(rec, "v", vault.Scope{Project: "p", Env: "prod"}); !ok || sc.Env != "prod" {
		t.Fatalf("own scope: %+v %v", sc, ok)
	}
	if sc, ok := refreshScope(rec, "v", vault.Scope{Project: "p", Env: "default"}); !ok || sc != (vault.Scope{Project: "p", Env: "prod"}) {
		t.Fatalf("default write: %+v %v", sc, ok)
	}
	if _, ok := refreshScope(rec, "v", vault.Scope{Project: "p", Env: "stg"}); ok {
		t.Fatal("a sibling env's write must not re-seal prod")
	}
	if _, ok := refreshScope(rec, "v", vault.Scope{Project: "other", Env: "default"}); ok {
		t.Fatal("another project's default must not re-seal prod")
	}
	if _, ok := refreshScope(rec, "w", vault.Scope{Project: "p", Env: "default"}); ok {
		t.Fatal("another vault must not re-seal prod")
	}
}

func TestNeedsDefaultKeys(t *testing.T) {
	capKey := make([]byte, 32)
	with, err := vcrypto.SealCapability(capKey, map[string][]byte{vault.CapDefaultAuthoredKeyName: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	without, err := vcrypto.SealCapability(capKey, map[string][]byte{vault.CapScopeKeyName: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	prod := vault.Scope{Project: "p", Env: "prod"}
	if needsDefaultKeys(capKey, with, prod) {
		t.Fatal("a capability carrying default's key needs nothing")
	}
	if !needsDefaultKeys(capKey, without, prod) {
		t.Fatal("an old capability needs default's keys")
	}
	if !needsDefaultKeys(capKey, []byte("garbage"), prod) {
		t.Fatal("an unopenable capability reads as needing them")
	}
	if needsDefaultKeys(capKey, without, vault.Scope{Project: "p", Env: "default"}) {
		t.Fatal("a default-env grant inherits nothing")
	}
}

func TestIsReservedCapName(t *testing.T) {
	for _, n := range []string{vault.CapScopeKeyName, vault.CapAuthoredKeyName, vault.CapDefaultScopeKeyName, vault.CapDefaultAuthoredKeyName} {
		if !isReservedCapName(n) {
			t.Fatalf("%q should be reserved", n)
		}
	}
	if isReservedCapName("API_KEY") {
		t.Fatal("a variable name is not reserved")
	}
}

func TestSelectUnattended(t *testing.T) {
	all := []vault.UnattendedEntry{
		{Project: "p", Env: "default", Name: "B"},
		{Project: "p", Env: "default", Name: "A"},
		{Project: "p", Env: "prod", Name: "C"},
		{Project: "q", Env: "default", Name: "D"},
	}
	got, skipped := selectUnattended(all, vault.Scope{Project: "p", Env: "default"}, nil, false)
	if len(got) != 2 || got[0].Name != "A" || got[1].Name != "B" || skipped != nil {
		t.Fatalf("scope: %+v %+v", got, skipped)
	}
	if got, _ := selectUnattended(all, vault.Scope{}, nil, true); len(got) != 4 {
		t.Fatalf("all: %+v", got)
	}
	got, skipped = selectUnattended(all, vault.Scope{Project: "p", Env: "prod"}, []string{"C", "A", "Z"}, false)
	if len(got) != 1 || got[0].Name != "C" || len(skipped) != 2 ||
		!strings.Contains(skipped[0].Reason, "--env default") || !strings.Contains(skipped[1].Reason, "not an unattended value") {
		t.Fatalf("named: %+v %+v", got, skipped)
	}
}

func TestWildcardNotDelivered_HonoursOptional(t *testing.T) {
	d, _, _ := inheritFixture(t, prodWildcardByn)
	st := d.vaults["default"].store
	missing := d.wildcardNotDelivered(context.Background(), st, vault.Scope{Project: "default", Env: "prod"},
		[]string{"AUTH_KEY"}, []ipc.ExecFetchValue{{Name: "SEED"}})
	if len(missing) != 0 {
		t.Fatalf("missing = %v, want none (SEED delivered, AUTH_KEY optional)", missing)
	}
}

// A grant made while the vault is locked (password path) must carry default's
// keys too; the in-memory key is not available then.
func TestLockedGrantWithPasswordCarriesDefaultKeys(t *testing.T) {
	_ = stubOrigin(t, true)
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "prod"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatal(err)
	}
	lockVaultStore(t, d, "default")
	c.Session = nil
	grantBynFile(t, c, writeBynContent(t, prodWildcardByn), pw)

	store, err := trust.Load(d.cfg.Dir)
	if err != nil {
		t.Fatal(err)
	}
	capKey, err := vcrypto.DeriveCapKey(d.fpMACKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range store.Records {
		if r.ScopeEnv != "prod" {
			continue
		}
		keys, err := vcrypto.OpenCapability(capKey, r.ExecCapability)
		if err != nil {
			t.Fatal(err)
		}
		if len(keys[vault.CapDefaultAuthoredKeyName]) == 0 || len(keys[vault.CapDefaultScopeKeyName]) == 0 {
			t.Fatalf("locked grant lacks default keys: %d entries", len(keys))
		}
		return
	}
	t.Fatal("no prod record")
}

func TestCaptureDefaultKeysInto(t *testing.T) {
	d, c2 := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c2, pw)
	if err := c2.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "prod"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatal(err)
	}
	st := d.vaults["default"].store
	ctx := context.Background()
	prod := vault.Scope{Project: "default", Env: "prod"}

	var keys map[string][]byte
	if err := captureDefaultKeysInto(ctx, st, vault.Scope{Project: "default", Env: "default"}, true, true, nil, nil, &keys); err != nil || keys != nil {
		t.Fatalf("default env: keys=%v err=%v", keys, err)
	}
	st.Lock()
	vk, err := st.UnwrapVaultKey(pw)
	if err != nil {
		t.Fatal(err)
	}
	keys = nil
	if err := captureDefaultKeysInto(ctx, st, prod, false, false, nil, vk, &keys); err != nil ||
		len(keys[vault.CapDefaultAuthoredKeyName]) == 0 || keys[vault.CapDefaultScopeKeyName] != nil {
		t.Fatalf("explicit grant via key: %d entries err=%v", len(keys), err)
	}
	keys = nil
	if err := captureDefaultKeysInto(ctx, st, prod, true, false, pw, nil, &keys); err != nil || len(keys) != 2 {
		t.Fatalf("wildcard via password: %d entries err=%v", len(keys), err)
	}
	if err := captureDefaultKeysInto(ctx, st, prod, true, false, []byte("wrong"), nil, &keys); err == nil {
		t.Fatal("a wrong password must fail the capture")
	}
	if err := captureDefaultKeysInto(ctx, st, prod, true, false, nil, nil, &keys); err == nil {
		t.Fatal("locked with no key or password must fail")
	}
}
