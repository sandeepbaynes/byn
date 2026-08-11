package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Sync keys. Each is derived from the vault key under its own domain separator,
// so one of them leaking says nothing about the others and none can be confused
// for a row key.
//
// The split exists because a sync server sees more than a local disk does. On
// disk, entry names are plaintext: anyone who can read the file already holds
// the ciphertext, so hiding names buys nothing. A server holds the same blobs
// for every user and is a single place worth attacking, so the names go under
// K_meta and the identifiers become opaque under K_id. A server that is fully
// compromised should learn how many secrets exist and when they changed — not
// that one of them is called STRIPE_LIVE_KEY.
const (
	metaKeyInfo = "byn/sync/meta/v1\x00"
	idKeyInfo   = "byn/sync/id/v1\x00"
	logKeyInfo  = "byn/sync/log/v1\x00"
)

// DeriveSyncMetaKey returns the key that encrypts names and paths in sync
// records. Callers must zero it.
func DeriveSyncMetaKey(vaultKey []byte) ([]byte, error) {
	if len(vaultKey) != VaultKeySize {
		return nil, ErrBadKey
	}
	return expand(vaultKey, metaKeyInfo, nil)
}

// DeriveSyncIDKey returns the key that turns an entry's identity into an opaque
// server-side record id. Callers must zero it.
func DeriveSyncIDKey(vaultKey []byte) ([]byte, error) {
	if len(vaultKey) != VaultKeySize {
		return nil, ErrBadKey
	}
	return expand(vaultKey, idKeyInfo, nil)
}

// DeriveSyncLogKey returns the key that encrypts console lines and the
// human-readable detail of an approval request. Callers must zero it.
func DeriveSyncLogKey(vaultKey []byte) ([]byte, error) {
	if len(vaultKey) != VaultKeySize {
		return nil, ErrBadKey
	}
	return expand(vaultKey, logKeyInfo, nil)
}

// SyncRecordID maps an entry's stable identity to the id the server files it
// under.
//
// It is an HMAC rather than a hash so the mapping cannot be reversed by anyone
// without the vault key. A plain hash of the name would let a server confirm a
// guess — "is one of these DATABASE_URL?" — by hashing candidates itself, and
// the answer to that question is usually yes, which is exactly what the naming
// is meant to withhold.
//
// The result is deterministic, so the same entry keeps its id across machines
// and syncs converge without coordination.
func SyncRecordID(idKey []byte, vaultID, kind, name string) string {
	mac := hmac.New(sha256.New, idKey)
	// Length-prefix-free but separator-delimited, matching entryAAD: 0x1F
	// cannot appear in a vault id, and the kinds are a closed set.
	mac.Write([]byte(vaultID))
	mac.Write([]byte{0x1F})
	mac.Write([]byte(kind))
	mac.Write([]byte{0x1F})
	mac.Write([]byte(name))
	return hex.EncodeToString(mac.Sum(nil))
}
