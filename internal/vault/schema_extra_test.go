package vault

import (
	"context"
	"testing"
)

func TestMetaGetSet_RoundTrip(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if got, err := st.MetaGet(ctx, "nope"); err != nil || got != "" {
		t.Fatalf("missing key: got %q err=%v", got, err)
	}
	if err := st.MetaSet(ctx, "key", "value"); err != nil {
		t.Fatalf("MetaSet: %v", err)
	}
	got, err := st.MetaGet(ctx, "key")
	if err != nil {
		t.Fatalf("MetaGet: %v", err)
	}
	if got != "value" {
		t.Fatalf("got %q", got)
	}
	// Overwrite.
	if err := st.MetaSet(ctx, "key", "v2"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, _ = st.MetaGet(ctx, "key")
	if got != "v2" {
		t.Fatalf("got %q", got)
	}
}
