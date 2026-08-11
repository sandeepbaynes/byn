package syncbridge

import (
	"strings"
	"testing"

	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

func testKeys(t *testing.T) (metaKey, idKey []byte) {
	t.Helper()
	vk := make([]byte, vcrypto.VaultKeySize)
	for i := range vk {
		vk[i] = byte(i + 1)
	}
	mk, err := vcrypto.DeriveSyncMetaKey(vk)
	if err != nil {
		t.Fatalf("meta key: %v", err)
	}
	ik, err := vcrypto.DeriveSyncIDKey(vk)
	if err != nil {
		t.Fatalf("id key: %v", err)
	}
	return mk, ik
}

func TestSealOpenMeta_RoundTrip(t *testing.T) {
	mk, _ := testKeys(t)
	blob, err := SealMeta(mk, "vault-1", "rec-1", "DB_URL", "env_var", "api", "prod")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	name, kind, project, env, err := OpenMeta(mk, "vault-1", "rec-1", blob)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if name != "DB_URL" || kind != "env_var" || project != "api" || env != "prod" {
		t.Fatalf("round trip lost fields: %q %q %q %q", name, kind, project, env)
	}
}

// The name is the whole reason metadata is sealed: a server holding every
// user's records must not learn that one of them is called STRIPE_LIVE_KEY.
func TestSealMeta_NameIsNotOnTheWire(t *testing.T) {
	mk, _ := testKeys(t)
	blob, err := SealMeta(mk, "vault-1", "rec-1", "STRIPE_LIVE_KEY", "env_var", "", "")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if strings.Contains(string(blob), "STRIPE_LIVE_KEY") {
		t.Fatal("the entry name appears in the sealed blob")
	}
}

// Metadata is bound to the record it describes, so a server cannot move one
// entry's name onto another entry's ciphertext and have it accepted.
func TestSealMeta_BoundToItsRecord(t *testing.T) {
	mk, _ := testKeys(t)
	blob, err := SealMeta(mk, "vault-1", "rec-1", "DB_URL", "env_var", "", "")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, _, _, _, err := OpenMeta(mk, "vault-1", "rec-2", blob); err == nil {
		t.Error("metadata opened under a different record id")
	}
	if _, _, _, _, err := OpenMeta(mk, "vault-2", "rec-1", blob); err == nil {
		t.Error("metadata opened under a different vault id")
	}
}

// The id has to be stable, so machines converge on the same record without
// coordinating, and opaque, so a server cannot confirm a guess about the name.
func TestSyncRecordID(t *testing.T) {
	_, ik := testKeys(t)
	a := vcrypto.SyncRecordID(ik, "vault-1", "env_var", "DB_URL")
	if a != vcrypto.SyncRecordID(ik, "vault-1", "env_var", "DB_URL") {
		t.Error("id is not deterministic; machines would not converge")
	}
	if strings.Contains(a, "DB_URL") {
		t.Error("id leaks the entry name")
	}
	for _, other := range []struct{ vault, kind, name string }{
		{"vault-2", "env_var", "DB_URL"},
		{"vault-1", "file", "DB_URL"},
		{"vault-1", "env_var", "OTHER"},
	} {
		if vcrypto.SyncRecordID(ik, other.vault, other.kind, other.name) == a {
			t.Errorf("id collides across %+v", other)
		}
	}

	// A different vault key must produce different ids, or two users' servers
	// could be correlated by identifier alone.
	vk2 := make([]byte, vcrypto.VaultKeySize)
	for i := range vk2 {
		vk2[i] = byte(200 - i)
	}
	ik2, err := vcrypto.DeriveSyncIDKey(vk2)
	if err != nil {
		t.Fatalf("id key 2: %v", err)
	}
	if vcrypto.SyncRecordID(ik2, "vault-1", "env_var", "DB_URL") == a {
		t.Error("ids are identical under different vault keys")
	}
}

// Every sync key must be distinct, so one leaking says nothing about the others.
func TestSyncKeys_AreDistinct(t *testing.T) {
	vk := make([]byte, vcrypto.VaultKeySize)
	for i := range vk {
		vk[i] = byte(i)
	}
	meta, _ := vcrypto.DeriveSyncMetaKey(vk)
	id, _ := vcrypto.DeriveSyncIDKey(vk)
	logk, _ := vcrypto.DeriveSyncLogKey(vk)
	row, err := vcrypto.DeriveRowKey(vk, []byte("ctx"))
	if err != nil {
		t.Fatalf("row key: %v", err)
	}
	keys := map[string][]byte{"meta": meta, "id": id, "log": logk, "row": row, "vault": vk}
	for an, a := range keys {
		for bn, b := range keys {
			if an < bn && string(a) == string(b) {
				t.Errorf("%s and %s keys are identical", an, bn)
			}
		}
	}
}

func TestRecord_Validate(t *testing.T) {
	base := Record{Version: FormatVersion, ID: "r1", VaultID: "v1", Value: []byte("ct")}
	if err := base.Validate("v1"); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	// A record for another vault means the server mixed up accounts, or is
	// probing. Either way it must not be applied.
	if err := base.Validate("v2"); err == nil {
		t.Error("record for a different vault was accepted")
	}
	if err := (Record{Version: FormatVersion, VaultID: "v1", Value: []byte("x")}).Validate("v1"); err == nil {
		t.Error("record with no id was accepted")
	}
	// Refusing a newer format explicitly beats failing at the AEAD, which would
	// look identical to tampering.
	newer := base
	newer.Version = FormatVersion + 1
	if err := newer.Validate("v1"); err == nil {
		t.Error("record from a newer byn was accepted")
	}
	// A tombstone legitimately carries no value.
	tomb := Record{Version: FormatVersion, ID: "r1", VaultID: "v1", Deleted: true}
	if err := tomb.Validate("v1"); err != nil {
		t.Errorf("tombstone rejected: %v", err)
	}
	live := Record{Version: FormatVersion, ID: "r1", VaultID: "v1"}
	if err := live.Validate("v1"); err == nil {
		t.Error("live record with no value was accepted")
	}
}

// Every peer must reach the SAME answer about which write wins, without
// talking to the others. An arbitrary rule applied identically converges; a
// reasonable rule applied differently does not.
func TestRecord_Newer_IsTotalAndSymmetric(t *testing.T) {
	a := Record{Lamport: 5, WallMS: 100, Device: "aaa"}
	b := Record{Lamport: 6, WallMS: 1, Device: "zzz"}
	if !b.Newer(a) || a.Newer(b) {
		t.Error("a higher lamport counter must win regardless of wall time")
	}

	// Equal counters: wall time breaks the tie.
	c := Record{Lamport: 5, WallMS: 200, Device: "aaa"}
	if !c.Newer(a) || a.Newer(c) {
		t.Error("wall time should break a lamport tie")
	}

	// Equal counters and equal wall time: the device id decides, and both sides
	// must agree on which one.
	d := Record{Lamport: 5, WallMS: 100, Device: "zzz"}
	if !d.Newer(a) || a.Newer(d) {
		t.Error("device id must break a full tie, the same way on both sides")
	}

	// Identical records: neither is newer, so a redelivery cannot flap.
	if a.Newer(a) {
		t.Error("a record reports itself as newer than itself")
	}
}
