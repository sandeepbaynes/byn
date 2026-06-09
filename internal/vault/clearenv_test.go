package vault

import (
	"context"
	"testing"
)

func TestClearEnvVars(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	for _, n := range []string{"A", "B", "C"} {
		if err := st.PutEnvVar(ctx, defaultScope(), n, []byte("v"), PutOpt{}); err != nil {
			t.Fatalf("put %s: %v", n, err)
		}
	}

	// Clear works while LOCKED — it deletes rows, no vault key needed.
	st.Lock()
	n, err := st.ClearEnvVars(ctx, defaultScope())
	if err != nil {
		t.Fatalf("ClearEnvVars: %v", err)
	}
	if n != 3 {
		t.Fatalf("cleared %d, want 3", n)
	}
	infos, err := st.ListEnvVars(ctx, defaultScope())
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 0 {
		t.Fatalf("env should be empty after clear, got %d entries", len(infos))
	}

	// Idempotent: clearing an already-empty env deletes nothing.
	n2, err := st.ClearEnvVars(ctx, defaultScope())
	if err != nil || n2 != 0 {
		t.Fatalf("re-clear = %d, %v; want 0, nil", n2, err)
	}
}
