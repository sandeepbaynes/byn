package vault

import (
	"context"
	"testing"
)

// TestListEnvVars_SameAsDefault guards the "is this copy really an
// override?" answer the UIs draw their badges from. A value that repeats
// default's must not read as an override, and the answer must be settled
// without the key whenever ciphertext lengths already decide it.
func TestListEnvVars_SameAsDefault(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.CreateEnv(ctx, DefaultProjectName, "local"); err != nil {
		t.Fatalf("CreateEnv: %v", err)
	}
	defaultS := defaultScope()
	localS := Scope{Project: DefaultProjectName, Env: "local"}

	put := func(sc Scope, name, val string) {
		t.Helper()
		if err := st.PutEnvVar(ctx, sc, name, []byte(val), PutOpt{}); err != nil {
			t.Fatalf("Put %s in %s: %v", name, sc.Env, err)
		}
	}
	put(defaultS, "SAME", "identical")
	put(localS, "SAME", "identical")
	put(defaultS, "DIFF_LEN", "short")
	put(localS, "DIFF_LEN", "a longer value")
	put(defaultS, "DIFF_SAME_LEN", "aaaa")
	put(localS, "DIFF_SAME_LEN", "bbbb")
	put(defaultS, "BOTH_EMPTY", "")
	put(localS, "BOTH_EMPTY", "")
	put(defaultS, "INHERITED", "base")
	put(localS, "LOCAL_ONLY", "mine")

	byName := func(infos []EntryInfo) map[string]EntryInfo {
		m := map[string]EntryInfo{}
		for _, i := range infos {
			m[i.Name] = i
		}
		return m
	}
	want := func(m map[string]EntryInfo, name string, inDefault bool, same *bool) {
		t.Helper()
		got := m[name]
		if got.InDefault != inDefault {
			t.Errorf("%s.InDefault = %v, want %v", name, got.InDefault, inDefault)
		}
		switch {
		case same == nil && got.SameAsDefault != nil:
			t.Errorf("%s.SameAsDefault = %v, want nil", name, *got.SameAsDefault)
		case same != nil && got.SameAsDefault == nil:
			t.Errorf("%s.SameAsDefault = nil, want %v", name, *same)
		case same != nil && *got.SameAsDefault != *same:
			t.Errorf("%s.SameAsDefault = %v, want %v", name, *got.SameAsDefault, *same)
		}
	}
	yes, no := true, false

	infos, err := st.ListEnvVars(ctx, localS)
	if err != nil {
		t.Fatalf("List local (unlocked): %v", err)
	}
	m := byName(infos)
	want(m, "SAME", true, &yes)
	want(m, "DIFF_LEN", true, &no)
	want(m, "DIFF_SAME_LEN", true, &no)
	want(m, "BOTH_EMPTY", true, &yes)
	want(m, "INHERITED", false, nil)
	want(m, "LOCAL_ONLY", false, nil)

	// Editing the copy back and forth flips the answer with it — the badge
	// must follow the value, not the moment the row was created.
	put(localS, "SAME", "changed")
	m = byName(mustList(t, st, localS))
	want(m, "SAME", true, &no)
	put(localS, "SAME", "identical")
	m = byName(mustList(t, st, localS))
	want(m, "SAME", true, &yes)

	// The default env itself never compares against anything.
	m = byName(mustList(t, st, defaultS))
	for name, info := range m {
		if info.InDefault || info.SameAsDefault != nil {
			t.Errorf("default env row %s carries comparison fields: %+v", name, info)
		}
	}

	// Locked: length alone still settles DIFF_LEN and BOTH_EMPTY; the
	// same-length pairs are undecidable and stay nil rather than guessed.
	st.Lock()
	infos, err = st.ListEnvVars(ctx, localS)
	if err != nil {
		t.Fatalf("List local (locked): %v", err)
	}
	m = byName(infos)
	want(m, "SAME", true, nil)
	want(m, "DIFF_SAME_LEN", true, nil)
	want(m, "DIFF_LEN", true, &no)
	want(m, "BOTH_EMPTY", true, &yes)
}

func mustList(t *testing.T, st *Store, sc Scope) []EntryInfo {
	t.Helper()
	infos, err := st.ListEnvVars(context.Background(), sc)
	if err != nil {
		t.Fatalf("List %s: %v", sc.Env, err)
	}
	return infos
}
