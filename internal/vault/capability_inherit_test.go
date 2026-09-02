package vault

import (
	"context"
	"errors"
	"testing"

	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

// TestCapability_GoesStaleWhenAnInheritedValueIsOverridden reproduces a failure
// reported from the field:
//
//	Error: decrypt "INTEGRATION_CONFIG_ENCRYPTION_KEY" via capability:
//	       vault/crypto: wrapped key tampered or corrupted
//
// Nothing was corrupted, and no .byn had been edited. One secret failed while
// others in the same env, same vault, decrypted normally in the same session —
// and `byn trust` fixed it instantly.
//
// The cause is inheritance. A capability captures the key that opens the row
// where the value ACTUALLY lives: for an inherited value that is the default
// env's row, keyed on the default env's id. A later `byn put` in the child env
// creates an override — a different row, in a different env, under a different
// key — and the captured key no longer opens it. The AEAD fails, and an AEAD
// failure is reported as tampering.
//
// So a plain `byn put` can invalidate a live capability for exactly one name
// without touching any file. That is the missing piece in the report: it is not
// the trust MAC that went stale, it is one captured row key.
func TestCapability_GoesStaleWhenAnInheritedValueIsOverridden(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()

	// The value lives only in the default env; the child env inherits it.
	base := defaultScope()
	if err := st.PutEnvVar(ctx, base, "SHARED_KEY", []byte("from-default"), PutOpt{}); err != nil {
		t.Fatalf("put in default: %v", err)
	}
	child := base
	child.Env = "stg"
	if err := st.CreateEnv(ctx, base.Project, "stg"); err != nil {
		t.Fatalf("create env: %v", err)
	}

	// Trust captures the key for the child scope. Inherited, so this is the
	// DEFAULT env's row key.
	keys, err := st.CaptureRowKeys(ctx, child, []string{"SHARED_KEY"})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	rk := keys["SHARED_KEY"]
	if rk == nil {
		t.Fatal("no key captured for an inherited value")
	}
	// It opens the inherited value, as it must.
	if v, oerr := st.OpenEnvVarWithRowKey(ctx, child, "SHARED_KEY", rk); oerr != nil ||
		string(v) != "from-default" {
		t.Fatalf("captured key must open the inherited value: %q %v", v, oerr)
	}

	// Now somebody overrides it in the child env. No file is touched.
	if err := st.PutEnvVar(ctx, child, "SHARED_KEY", []byte("stg-specific"), PutOpt{}); err != nil {
		t.Fatalf("override put: %v", err)
	}

	_, oerr := st.OpenEnvVarWithRowKey(ctx, child, "SHARED_KEY", rk)
	if oerr == nil {
		t.Fatal("expected the captured key to stop opening the row after an override")
	}
	// The shape of the failure is the whole point: an ordinary, recoverable
	// staleness arrives as an AEAD failure, which is the same signal real
	// ciphertext damage produces. Anything reading this as corruption is being
	// told the wrong thing.
	if !isTamperedErr(oerr) {
		t.Fatalf("want the AEAD-failure shape that produced the misleading report, got %v", oerr)
	}
	// And the value itself is fine — read it the ordinary way.
	e, gerr := st.GetEnvVar(ctx, child, "SHARED_KEY")
	if gerr != nil || string(e.Value) != "stg-specific" {
		t.Fatalf("the value is intact and readable: %q %v", e.Value, gerr)
	}
}

func isTamperedErr(err error) bool {
	return errors.Is(err, vcrypto.ErrTampered)
}
