package trust

import (
	"reflect"
	"testing"
)

func TestPutAndLookup(t *testing.T) {
	dir := t.TempDir()
	fpKey, vkKey := key(1), key(2)
	rec := Record{Path: "/p/.byn", SHA256: "abc", Vault: "default"}
	rec.SetMACs(fpKey, vkKey)

	if changed, err := Put(dir, rec); err != nil || changed {
		t.Fatalf("first Put: changed=%v err=%v", changed, err)
	}
	got, ok, err := Lookup(dir, "/p/.byn")
	if err != nil || !ok {
		t.Fatalf("Lookup: ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(got, rec) {
		t.Fatalf("Lookup mismatch:\n got %+v\nwant %+v", got, rec)
	}

	// Update with a different content hash ⇒ changed=true.
	rec2 := Record{Path: "/p/.byn", SHA256: "def", Vault: "default"}
	rec2.SetMACs(fpKey, vkKey)
	if changed, err := Put(dir, rec2); err != nil || !changed {
		t.Fatalf("update Put: changed=%v err=%v", changed, err)
	}
	// Re-Put identical ⇒ changed=false.
	if changed, err := Put(dir, rec2); err != nil || changed {
		t.Fatalf("idempotent Put: changed=%v err=%v", changed, err)
	}
	if _, ok, _ := Lookup(dir, "/nope/.byn"); ok {
		t.Fatal("Lookup found a nonexistent path")
	}
}

func TestVerify_Statuses(t *testing.T) {
	dir := t.TempDir()
	fpKey, vkKey := key(0xAA), key(0xBB)
	const path, hash = "/proj/.byn", "abc123"
	const mtime int64 = 1_700_000_000_000_000_000 // arbitrary fixed nanoseconds

	// No record ⇒ untrusted.
	if st, _, _, _ := Verify(dir, path, hash, mtime, fpKey, vkKey); st != VerifyUntrusted {
		t.Fatalf("no record: %s, want untrusted", st)
	}

	// v1 record: no mtime (IsV2=false). After the verify.go change, a v1 record
	// with valid v1 MACs is classified stale (authentic but pre-upgrade). A v1
	// record with no MACs at all is also stale (pre-hardening).
	recV1 := Record{Path: path, SHA256: hash, Vault: "default"}
	recV1.SetMACs(fpKey, vkKey)
	if _, err := Put(dir, recV1); err != nil {
		t.Fatal(err)
	}
	if st, _, _, _ := Verify(dir, path, hash, mtime, fpKey, vkKey); st != VerifyStale {
		t.Fatalf("v1 record: %s, want stale", st)
	}

	// Now seed a v2 record (mtime set → IsV2=true).
	dir2 := t.TempDir()
	rec := Record{Path: path, SHA256: hash, Vault: "default", MTimeUnixNano: mtime}
	rec.SetMACs(fpKey, vkKey)
	if _, err := Put(dir2, rec); err != nil {
		t.Fatal(err)
	}

	// Both layers verify (unlocked).
	if st, vk, _, _ := Verify(dir2, path, hash, mtime, fpKey, vkKey); st != VerifyTrusted || !vk {
		t.Fatalf("valid: %s vkChecked=%v, want trusted+true", st, vk)
	}
	// Locked (vkKey nil): fp-MAC alone, vkChecked=false.
	if st, vk, _, _ := Verify(dir2, path, hash, mtime, fpKey, nil); st != VerifyTrusted || vk {
		t.Fatalf("locked: %s vkChecked=%v, want trusted+false", st, vk)
	}
	// Content changed.
	if st, _, _, _ := Verify(dir2, path, "different-hash", mtime, fpKey, vkKey); st != VerifyChanged {
		t.Fatalf("changed: %s, want changed", st)
	}
	// mtime drift with same content → changed (v2 record).
	if st, _, _, _ := Verify(dir2, path, hash, mtime+1, fpKey, vkKey); st != VerifyChanged {
		t.Fatalf("mtime drift: %s, want changed", st)
	}
	// Cross-machine copy: different fp key ⇒ tampered.
	if st, _, _, _ := Verify(dir2, path, hash, mtime, key(0xCC), vkKey); st != VerifyTampered {
		t.Fatalf("cross-machine: %s, want tampered", st)
	}
	// Same-UID forge: wrong vault key ⇒ tampered (vk layer).
	if st, _, _, _ := Verify(dir2, path, hash, mtime, fpKey, key(0xDD)); st != VerifyTampered {
		t.Fatalf("wrong vault key: %s, want tampered", st)
	}

	// Pre-hardening record (no MACs) ⇒ stale (re-trust to protect).
	dir3 := t.TempDir()
	if _, err := Put(dir3, Record{Path: path, SHA256: hash}); err != nil {
		t.Fatal(err)
	}
	if st, _, _, _ := Verify(dir3, path, hash, mtime, fpKey, vkKey); st != VerifyStale {
		t.Fatalf("pre-hardening: %s, want stale", st)
	}
}
