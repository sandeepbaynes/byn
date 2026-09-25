package vault

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// inheritedFixture: an unlocked store with default + prod envs, OWNER_VAL
// stored the ordinary way in default, AGENT_VAL stored unattended in default,
// and the keys a prod wildcard grant would carry. Returned locked.
func inheritedFixture(t *testing.T) (st *Store, prod Scope, own, ownAuth []byte, dflt InheritedKeys) {
	t.Helper()
	ctx := context.Background()
	st, def, defAuth := authoredFixture(t)
	if err := st.CreateEnv(ctx, DefaultProjectName, "prod"); err != nil {
		t.Fatalf("create env: %v", err)
	}
	prod = Scope{Project: DefaultProjectName, Env: "prod"}
	if err := st.PutEnvVar(ctx, def, "OWNER_VAL", []byte("owner"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	var err error
	if own, err = st.CaptureScopeKey(ctx, prod); err != nil {
		t.Fatal(err)
	}
	if ownAuth, err = st.CaptureAuthoredKey(ctx, prod); err != nil {
		t.Fatal(err)
	}
	if dflt.Scope, dflt.Authored, err = st.CaptureDefaultKeys(ctx, prod, true, nil); err != nil {
		t.Fatalf("capture default keys: %v", err)
	}
	st.Lock()
	if err := st.PutEnvVarAuthored(ctx, def, "AGENT_VAL", []byte("agent"), defAuth, PutOpt{}); err != nil {
		t.Fatalf("authored put: %v", err)
	}
	return st, prod, own, ownAuth, dflt
}

func TestCaptureDefaultKeys_NothingForTheDefaultEnv(t *testing.T) {
	st, def, _ := authoredFixture(t)
	kenv, kauth, err := st.CaptureDefaultKeys(context.Background(), def, true, nil)
	if err != nil || kenv != nil || kauth != nil {
		t.Fatalf("default env: kenv=%v kauth=%v err=%v, want all nil", kenv, kauth, err)
	}
}

func TestCaptureDefaultKeys_ScopeKeyOnlyForWildcard(t *testing.T) {
	ctx := context.Background()
	st, _, _ := authoredFixture(t)
	if err := st.CreateEnv(ctx, DefaultProjectName, "prod"); err != nil {
		t.Fatal(err)
	}
	prod := Scope{Project: DefaultProjectName, Env: "prod"}
	kenv, kauth, err := st.CaptureDefaultKeys(ctx, prod, false, nil)
	if err != nil || kenv != nil || len(kauth) == 0 {
		t.Fatalf("explicit grant: kenv=%v kauth-len=%d err=%v", kenv, len(kauth), err)
	}
	st.Lock()
	if _, _, err := st.CaptureDefaultKeys(ctx, prod, true, nil); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked, no key: err = %v, want ErrLocked", err)
	}
}

func TestOpenEnvVarInherited_OpensBothSchemesWhileLocked(t *testing.T) {
	ctx := context.Background()
	st, prod, own, ownAuth, dflt := inheritedFixture(t)
	for name, want := range map[string]string{"OWNER_VAL": "owner", "AGENT_VAL": "agent"} {
		got, err := st.OpenEnvVarInherited(ctx, prod, name, own, ownAuth, dflt)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, []byte(want)) {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestOpenEnvVarInherited_WithoutDefaultKeysIsNamedUnreachable(t *testing.T) {
	ctx := context.Background()
	st, prod, own, ownAuth, _ := inheritedFixture(t)
	_, err := st.OpenEnvVarInherited(ctx, prod, "AGENT_VAL", own, ownAuth, InheritedKeys{})
	var u *UnreachableDetail
	if !errors.As(err, &u) || !u.Inherited || !u.Unattended || u.Name != "AGENT_VAL" {
		t.Fatalf("err = %v, want UnreachableDetail{inherited, unattended}", err)
	}
	if !errors.Is(err, ErrInheritedUnreachable) {
		t.Fatal("must unwrap to ErrInheritedUnreachable")
	}
	_, err = st.OpenEnvVarInherited(ctx, prod, "OWNER_VAL", own, ownAuth, InheritedKeys{})
	if !errors.As(err, &u) || !u.Inherited || u.Unattended {
		t.Fatalf("OWNER_VAL err = %v, want inherited, not unattended", err)
	}
	if _, err := st.OpenEnvVarInherited(ctx, prod, "NOPE", own, ownAuth, InheritedKeys{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent: err = %v", err)
	}
}

// Default's keys must not open prod's own rows, and prod's keys must not open
// default's: a swapped key fails authentication rather than decrypting.
func TestOpenEnvVarInherited_KeysAreNotInterchangeable(t *testing.T) {
	ctx := context.Background()
	st, prod, own, ownAuth, dflt := inheritedFixture(t)
	if _, err := st.OpenEnvVarInherited(ctx, prod, "AGENT_VAL", own, ownAuth,
		InheritedKeys{Scope: dflt.Scope, Authored: ownAuth}); err == nil {
		t.Fatal("prod's authored key opened default's authored row")
	}
	if _, err := st.OpenEnvVarInherited(ctx, prod, "OWNER_VAL", own, ownAuth,
		InheritedKeys{Scope: own}); err == nil {
		t.Fatal("prod's scope key opened default's row")
	}
}

func TestEntryOrigin(t *testing.T) {
	ctx := context.Background()
	st, prod, _, _, _ := inheritedFixture(t)
	for _, tc := range []struct {
		name                    string
		inherited, unatt, found bool
	}{
		{"OWNER_VAL", true, false, true},
		{"AGENT_VAL", true, true, true},
		{"NOPE", false, false, false},
	} {
		inh, un, f, err := st.EntryOrigin(ctx, prod, tc.name)
		if err != nil || inh != tc.inherited || un != tc.unatt || f != tc.found {
			t.Fatalf("%s: inherited=%v unattended=%v found=%v err=%v", tc.name, inh, un, f, err)
		}
	}
}

func TestSealUnattended_MovesTheValueUnderTheVaultKey(t *testing.T) {
	ctx := context.Background()
	st, _, defAuth := authoredFixture(t)
	def := Scope{Project: DefaultProjectName, Env: DefaultEnvName}
	st.Lock()
	if err := st.PutEnvVarAuthored(ctx, def, "AGENT_VAL", []byte("agent"), defAuth, PutOpt{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SealUnattended(ctx, def, "AGENT_VAL"); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked: err = %v, want ErrLocked", err)
	}
	vk, err := st.UnwrapVaultKey([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := st.SealUnattendedWithKey(ctx, vk, def, "AGENT_VAL")
	if err != nil || !sealed {
		t.Fatalf("seal: sealed=%v err=%v", sealed, err)
	}
	// Idempotent: a second pass has nothing to do.
	if again, err := st.SealUnattendedWithKey(ctx, vk, def, "AGENT_VAL"); err != nil || again {
		t.Fatalf("second seal: sealed=%v err=%v", again, err)
	}
	// The authored key no longer opens it; the vault key does.
	if _, err := st.OpenEnvVarAuthored(ctx, def, "AGENT_VAL", defAuth); err == nil {
		t.Fatal("the machine-held authored key still opens an imported value")
	}
	if err := st.Unlock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	e, err := st.GetEnvVar(ctx, def, "AGENT_VAL")
	if err != nil || !bytes.Equal(e.Value, []byte("agent")) {
		t.Fatalf("get after seal: %q %v", e.Value, err)
	}
	if left, err := st.ListUnattended(ctx); err != nil || len(left) != 0 {
		t.Fatalf("still listed as unattended: %v %v", left, err)
	}
	if _, err := st.SealUnattended(ctx, def, "NOPE"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent: err = %v", err)
	}
}

func TestListUnattended(t *testing.T) {
	ctx := context.Background()
	st, _, _, _, _ := inheritedFixture(t)
	got, err := st.ListUnattended(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (UnattendedEntry{Project: DefaultProjectName, Env: DefaultEnvName, Name: "AGENT_VAL"}) {
		t.Fatalf("got %+v", got)
	}
}

// The *WithKey variants must derive exactly what the in-memory forms do, or a
// grant sealed while locked would carry keys that open nothing.
func TestWithKeyVariantsMatchInMemory(t *testing.T) {
	ctx := context.Background()
	st, scope, authKey := authoredFixture(t)
	vk, err := st.UnwrapVaultKey([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := st.CaptureScopeKey(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.CaptureScopeKeyWithKey(ctx, vk, scope)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("scope key differs: err=%v", err)
	}
	c, err := st.CaptureAuthoredKeyWithKey(ctx, vk, scope)
	if err != nil || !bytes.Equal(authKey, c) {
		t.Fatalf("authored key differs: err=%v", err)
	}
	d1, err := st.DeriveSubkey("info")
	if err != nil {
		t.Fatal(err)
	}
	d2, err := DeriveSubkeyWithKey(vk, "info")
	if err != nil || !bytes.Equal(d1, d2) {
		t.Fatalf("subkey differs: err=%v", err)
	}
	if _, err := st.CaptureScopeKeyWithKey(ctx, vk, Scope{Project: "nope", Env: DefaultEnvName}); err == nil {
		t.Fatal("unknown project must error")
	}
	// Default keys from a supplied key, while locked.
	if err := st.CreateEnv(ctx, DefaultProjectName, "prod"); err != nil {
		t.Fatal(err)
	}
	st.Lock()
	kenv, kauth, err := st.CaptureDefaultKeys(ctx, Scope{Project: DefaultProjectName, Env: "prod"}, true, vk)
	if err != nil || !bytes.Equal(kenv, a) || !bytes.Equal(kauth, authKey) {
		t.Fatalf("default keys via supplied key: err=%v", err)
	}
	if _, _, err := st.CaptureDefaultKeys(ctx, Scope{Project: "nope", Env: "prod"}, true, vk); err == nil {
		t.Fatal("unknown project must error")
	}
}

func TestUnreachableDetail_Error(t *testing.T) {
	msg := unreachable("AUTH_KEY", true, true).Error()
	for _, want := range []string{"AUTH_KEY", "inherited=true", "unattended=true"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("%q lacks %q", msg, want)
		}
	}
}
