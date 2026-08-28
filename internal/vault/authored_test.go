package vault

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// authoredFixture returns an initialised, unlocked store plus the default
// scope's authored key, then locks the store — the state an agent actually
// meets.
func authoredFixture(t *testing.T) (*Store, Scope, []byte) {
	t.Helper()
	ctx := context.Background()
	st, err := Init(ctx, t.TempDir(), DefaultVaultName, []byte("pw"))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := st.Unlock([]byte("pw")); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	scope := Scope{Project: DefaultProjectName, Env: DefaultEnvName}
	authKey, err := st.CaptureAuthoredKey(ctx, scope)
	if err != nil {
		t.Fatalf("capture authored key: %v", err)
	}
	return st, scope, authKey
}

// The whole point: a locked vault can still take a value and give it back.
func TestAuthored_LockedVaultAcceptsAndReturnsAValue(t *testing.T) {
	ctx := context.Background()
	st, scope, authKey := authoredFixture(t)
	st.Lock()

	if !st.IsLocked() {
		t.Fatal("precondition: the store should be locked")
	}
	// The ordinary path cannot do this, which is the problem being solved.
	if err := st.PutEnvVar(ctx, scope, "AGENT_TOKEN", []byte("v1"), PutOpt{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("PutEnvVar on a locked vault: err = %v, want ErrLocked", err)
	}

	if err := st.PutEnvVarAuthored(ctx, scope, "AGENT_TOKEN", []byte("v1"), authKey, PutOpt{CreateOnly: true}); err != nil {
		t.Fatalf("locked put: %v", err)
	}
	got, err := st.OpenEnvVarAuthored(ctx, scope, "AGENT_TOKEN", authKey)
	if err != nil {
		t.Fatalf("locked read-back: %v", err)
	}
	if !bytes.Equal(got, []byte("v1")) {
		t.Fatalf("read back %q, want v1", got)
	}

	// And updating its own value, still locked.
	if err := st.PutEnvVarAuthored(ctx, scope, "AGENT_TOKEN", []byte("v2"), authKey, PutOpt{}); err != nil {
		t.Fatalf("locked update: %v", err)
	}
	got, err = st.OpenEnvVarAuthored(ctx, scope, "AGENT_TOKEN", authKey)
	if err != nil {
		t.Fatalf("locked read-back after update: %v", err)
	}
	if !bytes.Equal(got, []byte("v2")) {
		t.Fatalf("read back %q, want v2", got)
	}
}

// The containment claim: the key that lets an agent write must not open the
// secrets that were already in the vault. If this ever passes, the feature has
// turned a locked vault into an open one.
func TestAuthored_KeyCannotOpenPreExistingSecrets(t *testing.T) {
	ctx := context.Background()
	st, scope, authKey := authoredFixture(t)

	// A secret stored the ordinary way, by a human with the password.
	if err := st.PutEnvVar(ctx, scope, "AWS_SECRET", []byte("pre-existing"), PutOpt{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	st.Lock()

	_, err := st.OpenEnvVarAuthored(ctx, scope, "AWS_SECRET", authKey)
	if err == nil {
		t.Fatal("the authored key opened a secret it did not write — a locked vault would be no lock at all")
	}
	if !errors.Is(err, errAuthoredKeyUnsupported) {
		t.Fatalf("err = %v, want errAuthoredKeyUnsupported (a clear refusal, not a decrypt failure)", err)
	}
}

// The master password stays a complete answer: unlocking opens what the agent
// wrote, so nothing an agent stores is beyond its owner's reach.
func TestAuthored_MasterPasswordStillOpensWhatTheAgentWrote(t *testing.T) {
	ctx := context.Background()
	st, scope, authKey := authoredFixture(t)
	st.Lock()

	if err := st.PutEnvVarAuthored(ctx, scope, "AGENT_TOKEN", []byte("written-locked"), authKey, PutOpt{}); err != nil {
		t.Fatalf("locked put: %v", err)
	}
	if err := st.Unlock([]byte("pw")); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	e, err := st.GetEnvVar(ctx, scope, "AGENT_TOKEN")
	if err != nil {
		t.Fatalf("get after unlock: %v", err)
	}
	if !bytes.Equal(e.Value, []byte("written-locked")) {
		t.Fatalf("value = %q, want written-locked", e.Value)
	}
}

// A key for one scope must not write or read another's.
func TestAuthored_KeyIsScoped(t *testing.T) {
	ctx := context.Background()
	st, scope, authKey := authoredFixture(t)
	if err := st.CreateEnv(ctx, DefaultProjectName, "prod"); err != nil {
		t.Fatalf("create env: %v", err)
	}
	other := Scope{Project: DefaultProjectName, Env: "prod"}
	otherKey, err := st.CaptureAuthoredKey(ctx, other)
	if err != nil {
		t.Fatalf("capture other: %v", err)
	}
	if bytes.Equal(authKey, otherKey) {
		t.Fatal("two envs share one authored key — a grant on one would cover the other")
	}
	st.Lock()

	if err := st.PutEnvVarAuthored(ctx, scope, "K", []byte("default-env"), authKey, PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := st.OpenEnvVarAuthored(ctx, scope, "K", otherKey); err == nil {
		t.Fatal("another env's authored key opened this env's entry")
	}
}

// Writing needs a key. Passing none must be refused rather than silently
// storing something nobody can read.
func TestAuthored_RefusesWithoutAKey(t *testing.T) {
	ctx := context.Background()
	st, scope, _ := authoredFixture(t)
	st.Lock()
	if err := st.PutEnvVarAuthored(ctx, scope, "K", []byte("v"), nil, PutOpt{}); !errors.Is(err, ErrLocked) {
		t.Errorf("put with no key: err = %v, want ErrLocked", err)
	}
	if _, err := st.OpenEnvVarAuthored(ctx, scope, "K", nil); !errors.Is(err, ErrLocked) {
		t.Errorf("open with no key: err = %v, want ErrLocked", err)
	}
}

// CreateOnly must still distinguish a create from an overwrite on this path —
// authorization upstream is built on that distinction.
func TestAuthored_CreateOnlyStillReportsExists(t *testing.T) {
	ctx := context.Background()
	st, scope, authKey := authoredFixture(t)
	st.Lock()
	if err := st.PutEnvVarAuthored(ctx, scope, "K", []byte("first"), authKey, PutOpt{CreateOnly: true}); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := st.PutEnvVarAuthored(ctx, scope, "K", []byte("second"), authKey, PutOpt{CreateOnly: true}); !errors.Is(err, ErrExists) {
		t.Fatalf("second: err = %v, want ErrExists", err)
	}
}
