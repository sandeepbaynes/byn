package vault

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func storedBlob(t *testing.T, st *Store, name string) []byte {
	t.Helper()
	var b []byte
	if err := st.db.QueryRowContext(context.Background(),
		`SELECT value FROM entries WHERE kind='env_var' AND name=?`, name).Scan(&b); err != nil {
		t.Fatalf("read stored value for %q: %v", name, err)
	}
	return b
}

// An unsecure value is readable with the vault locked and no key at all, and a
// sealed one is not reachable by the same call.
func TestUnsecure_ReadableWhileLocked(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVarUnsecure(ctx, defaultScope(), "PORT", []byte("8080"), PutOpt{}); err != nil {
		t.Fatalf("put unsecure: %v", err)
	}
	if err := st.PutEnvVar(ctx, defaultScope(), "API_KEY", []byte("s3cret"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	st.Lock()

	e, ok, err := st.UnsecureEnvVar(ctx, defaultScope(), "PORT")
	if err != nil || !ok {
		t.Fatalf("UnsecureEnvVar(PORT) ok=%v err=%v, want a value", ok, err)
	}
	if string(e.Value) != "8080" || !e.Unsecure {
		t.Fatalf("PORT = %q unsecure=%v", e.Value, e.Unsecure)
	}
	if _, ok, err := st.UnsecureEnvVar(ctx, defaultScope(), "API_KEY"); err != nil || ok {
		t.Fatalf("UnsecureEnvVar(API_KEY) ok=%v err=%v, want not ok", ok, err)
	}
	if _, ok, err := st.UnsecureEnvVar(ctx, defaultScope(), "ABSENT"); err != nil || ok {
		t.Fatalf("UnsecureEnvVar(ABSENT) ok=%v err=%v, want not ok", ok, err)
	}
	// A write is another matter: the row carries a MAC, and a locked vault
	// with no key offered has nothing to make one with.
	if err := st.PutEnvVarUnsecure(ctx, defaultScope(), "REGION", []byte("eu"), PutOpt{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked put unsecure = %v, want ErrLocked", err)
	}
	// The scope's authored key is enough — what a grant carries, or what the
	// master password yields without unlocking.
	ak, err := st.CaptureAuthoredKeyWithPassword(ctx, []byte(testPassword), defaultScope())
	if err != nil {
		t.Fatalf("capture authored key: %v", err)
	}
	if err := st.PutEnvVarUnsecureWithKey(ctx, ak, defaultScope(), "REGION", []byte("eu"), PutOpt{CreateOnly: true}); err != nil {
		t.Fatalf("locked put unsecure with key: %v", err)
	}
	if err := st.PutEnvVarUnsecureWithKey(ctx, ak, defaultScope(), "REGION", []byte("us"), PutOpt{CreateOnly: true}); !errors.Is(err, ErrExists) {
		t.Fatalf("create-only over existing = %v, want ErrExists", err)
	}
	// And a value written that way checks out once the vault is open.
	if err := st.Unlock([]byte(testPassword)); err != nil {
		t.Fatal(err)
	}
	if e, ok, err := st.UnsecureEnvVar(ctx, defaultScope(), "REGION"); err != nil || !ok || string(e.Value) != "eu" {
		t.Fatalf("REGION after unlock = %q ok=%v err=%v", e.Value, ok, err)
	}
}

func setStoredBlob(t *testing.T, st *Store, name string, blob []byte) {
	t.Helper()
	if _, err := st.db.ExecContext(context.Background(),
		`UPDATE entries SET value=? WHERE kind='env_var' AND name=?`, blob, name); err != nil {
		t.Fatalf("rewrite stored value for %q: %v", name, err)
	}
}

// An unsecure row rewritten behind byn's back is refused wherever a key is at
// hand to check it, and a listing still works so the owner can find it.
func TestUnsecure_TamperedRowIsRefused(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVarUnsecure(ctx, defaultScope(), "API_URL", []byte("https://api.example"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	good := storedBlob(t, st, "API_URL")
	if len(good) != plainHeaderLen+len("https://api.example") {
		t.Fatalf("stored blob is %d bytes, want header + value", len(good))
	}

	// The value changed, the MAC kept.
	evil := append(append([]byte{}, good[:plainHeaderLen]...), []byte("https://evil.example")...)
	setStoredBlob(t, st, "API_URL", evil)
	if _, _, err := st.UnsecureEnvVar(ctx, defaultScope(), "API_URL"); !errors.Is(err, ErrPlainTampered) {
		t.Fatalf("read of altered value = %v, want ErrPlainTampered", err)
	}
	if _, err := st.GetEnvVar(ctx, defaultScope(), "API_URL"); !errors.Is(err, ErrPlainTampered) {
		t.Fatalf("GetEnvVar of altered value = %v, want ErrPlainTampered", err)
	}
	if _, err := st.SetEnvVarsSecure(ctx, defaultScope(), []string{"API_URL"}, true); !errors.Is(err, ErrPlainTampered) {
		t.Fatalf("sealing an altered value = %v, want ErrPlainTampered", err)
	}
	if _, err := st.ListEnvVars(ctx, defaultScope()); err != nil {
		t.Fatalf("listing with an altered row: %v", err)
	}

	// A bare value with no header at all: what a hand-written row looks like.
	setStoredBlob(t, st, "API_URL", []byte("https://evil.example"))
	if _, _, err := st.UnsecureEnvVar(ctx, defaultScope(), "API_URL"); !errors.Is(err, ErrPlainTampered) {
		t.Fatalf("read of headerless value = %v, want ErrPlainTampered", err)
	}

	// A genuine row moved to another name does not verify there.
	if err := st.PutEnvVarUnsecure(ctx, defaultScope(), "OTHER", []byte("x"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	setStoredBlob(t, st, "OTHER", good)
	if _, _, err := st.UnsecureEnvVar(ctx, defaultScope(), "OTHER"); !errors.Is(err, ErrPlainTampered) {
		t.Fatalf("read of transplanted row = %v, want ErrPlainTampered", err)
	}

	// Locked with a grant's key: still checked. Locked with none: there is
	// nothing to check with, and the value is returned as it stands.
	ak, err := st.CaptureAuthoredKey(ctx, defaultScope())
	if err != nil {
		t.Fatal(err)
	}
	setStoredBlob(t, st, "API_URL", evil)
	st.Lock()
	if _, _, err := st.UnsecureEnvVarWithKeys(ctx, defaultScope(), "API_URL", PlainKeys{Own: ak}); !errors.Is(err, ErrPlainTampered) {
		t.Fatalf("locked read with a key = %v, want ErrPlainTampered", err)
	}
	if e, ok, err := st.UnsecureEnvVar(ctx, defaultScope(), "API_URL"); err != nil || !ok || string(e.Value) != "https://evil.example" {
		t.Fatalf("locked read with no key = %q ok=%v err=%v, want the stored value unchecked", e.Value, ok, err)
	}

	// Writing the value again is the repair.
	if err := st.PutEnvVarUnsecureWithKey(ctx, ak, defaultScope(), "API_URL", []byte("https://api.example"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := st.UnsecureEnvVarWithKeys(ctx, defaultScope(), "API_URL", PlainKeys{Own: ak}); err != nil || !ok {
		t.Fatalf("read after repair ok=%v err=%v", ok, err)
	}
}

// The listing says which entries are unsecure and gets emptiness right for
// both kinds, since they are different sizes on disk.
func TestUnsecure_Listing(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.PutEnvVarUnsecure(ctx, defaultScope(), "PLAIN", []byte("v"), PutOpt{}))
	must(st.PutEnvVarUnsecure(ctx, defaultScope(), "PLAIN_EMPTY", nil, PutOpt{}))
	must(st.PutEnvVar(ctx, defaultScope(), "SEALED", []byte("v"), PutOpt{}))
	must(st.PutEnvVar(ctx, defaultScope(), "SEALED_EMPTY", nil, PutOpt{}))

	infos, err := st.ListEnvVars(ctx, defaultScope())
	must(err)
	got := map[string]EntryInfo{}
	for _, i := range infos {
		got[i.Name] = i
	}
	for name, want := range map[string]struct{ unsecure, empty bool }{
		"PLAIN": {true, false}, "PLAIN_EMPTY": {true, true},
		"SEALED": {false, false}, "SEALED_EMPTY": {false, true},
	} {
		i := got[name]
		if i.Unsecure != want.unsecure || i.IsEmpty != want.empty {
			t.Errorf("%s: unsecure=%v empty=%v, want %v/%v", name, i.Unsecure, i.IsEmpty, want.unsecure, want.empty)
		}
	}
}

// An override is compared with default by value, not by stored size: a sealed
// value and an unsecure one holding the same bytes are equal.
func TestUnsecure_SameAsDefaultAcrossSchemes(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.CreateEnv(ctx, DefaultProjectName, "dev"); err != nil {
		t.Fatal(err)
	}
	dev := Scope{Project: DefaultProjectName, Env: "dev"}
	if err := st.PutEnvVar(ctx, defaultScope(), "A", []byte("same"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnvVarUnsecure(ctx, dev, "A", []byte("same"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnvVar(ctx, defaultScope(), "B", []byte("one"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnvVarUnsecure(ctx, dev, "B", []byte("other"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	infos, err := st.ListEnvVars(ctx, dev)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range infos {
		if i.SameAsDefault == nil {
			t.Fatalf("%s: SameAsDefault undecided", i.Name)
		}
		if want := i.Name == "A"; *i.SameAsDefault != want {
			t.Errorf("%s: SameAsDefault=%v, want %v", i.Name, *i.SameAsDefault, want)
		}
	}
}

// Flipping moves the stored bytes between sealed and raw, both ways, and the
// value reads the same throughout.
func TestSetEnvVarsSecure_RoundTrip(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "URL", []byte("https://x"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	ch, err := st.SetEnvVarsSecure(ctx, defaultScope(), []string{"URL", "URL"}, false)
	if err != nil {
		t.Fatalf("unsecure: %v", err)
	}
	if len(ch) != 1 || !ch[0].Changed {
		t.Fatalf("changes = %+v, want one changed", ch)
	}
	if b := storedBlob(t, st, "URL"); len(b) < plainHeaderLen || !bytes.Equal(b[plainHeaderLen:], []byte("https://x")) {
		t.Fatalf("stored value does not hold the raw bytes after unsecure")
	}
	if ch, _ := st.SetEnvVarsSecure(ctx, defaultScope(), []string{"URL"}, false); len(ch) != 1 || ch[0].Changed {
		t.Fatalf("second unsecure = %+v, want unchanged", ch)
	}

	if _, err := st.SetEnvVarsSecure(ctx, defaultScope(), []string{"URL"}, true); err != nil {
		t.Fatalf("secure: %v", err)
	}
	if bytes.Contains(storedBlob(t, st, "URL"), []byte("https://x")) {
		t.Fatalf("stored value still contains the plaintext after secure")
	}
	if v := rowAADVersion(t, st, "URL"); v != currentAADVersion {
		t.Fatalf("aad_version=%d after secure, want %d", v, currentAADVersion)
	}
	e, err := st.GetEnvVar(ctx, defaultScope(), "URL")
	if err != nil || string(e.Value) != "https://x" || e.Unsecure {
		t.Fatalf("get after secure = %q unsecure=%v err=%v", e.Value, e.Unsecure, err)
	}
	if _, ok, _ := st.UnsecureEnvVar(ctx, defaultScope(), "URL"); ok {
		t.Fatalf("a secured value is still readable without a key")
	}
}

// One bad name changes nothing: the flip is all or none.
func TestSetEnvVarsSecure_AllOrNone(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "A", []byte("a"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	_, err := st.SetEnvVarsSecure(ctx, defaultScope(), []string{"A", "MISSING"}, false)
	var ne *NameError
	if !errors.As(err, &ne) || ne.Name != "MISSING" || !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want NameError{MISSING, ErrNotFound}", err)
	}
	if _, ok, _ := st.UnsecureEnvVar(ctx, defaultScope(), "A"); ok {
		t.Fatalf("A was made unsecure although the call failed")
	}
}

// A name that exists only by inheritance is refused, not silently changed for
// every env that inherits it.
func TestSetEnvVarsSecure_RefusesInherited(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.CreateEnv(ctx, DefaultProjectName, "dev"); err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnvVar(ctx, defaultScope(), "SHARED", []byte("v"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	_, err := st.SetEnvVarsSecure(ctx, Scope{Project: DefaultProjectName, Env: "dev"}, []string{"SHARED"}, false)
	if !errors.Is(err, ErrInheritedEntry) {
		t.Fatalf("err = %v, want ErrInheritedEntry", err)
	}
}

func TestSetEnvVarsSecure_NeedsKey(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVarUnsecure(ctx, defaultScope(), "A", []byte("a"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	st.Lock()
	if _, err := st.SetEnvVarsSecure(ctx, defaultScope(), []string{"A"}, true); !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked", err)
	}
}

// A sealed write over an unsecure entry seals it: unsecure never carries over
// to a write that did not ask for it.
func TestUnsecure_SealedPutReplacesIt(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVarUnsecure(ctx, defaultScope(), "TOKEN", []byte("placeholder"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnvVar(ctx, defaultScope(), "TOKEN", []byte("the-real-one"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(storedBlob(t, st, "TOKEN"), []byte("the-real-one")) {
		t.Fatalf("a sealed put over an unsecure entry stored the value in the clear")
	}
	if _, ok, _ := st.UnsecureEnvVar(ctx, defaultScope(), "TOKEN"); ok {
		t.Fatalf("entry still reads as unsecure after a sealed put")
	}
}

// Renaming keeps an unsecure value unsecure.
func TestUnsecure_RenameKeepsIt(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVarUnsecure(ctx, defaultScope(), "OLD", []byte("v"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	if err := st.RenameEnvVar(ctx, defaultScope(), "OLD", "NEW"); err != nil {
		t.Fatal(err)
	}
	e, ok, err := st.UnsecureEnvVar(ctx, defaultScope(), "NEW")
	if err != nil || !ok || string(e.Value) != "v" {
		t.Fatalf("NEW ok=%v value=%q err=%v", ok, e.Value, err)
	}
}
