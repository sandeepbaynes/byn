package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// rowKeyInfoPrefix domain-separates per-row keys from every other HKDF subkey
// derived from the vault key (trust MACs, file-meta MAC, etc.) so a row key can
// never collide with another purpose's subkey. Bump the suffix on any
// incompatible change to the derivation.
const rowKeyInfoPrefix = "byn/row-key/v1\x00"

// DeriveRowKey derives the per-row encryption key for the row identified by
// context — the caller's STABLE row identity (e.g. vaultID‖kind‖name, the same
// bytes used as the entry AAD) — from the vault key via HKDF-SHA256.
//
// Per-row keys are the foundation of autonomous trusted-.byn exec: the daemon
// can hand out (store) the decryption capability for the SPECIFIC rows a
// trusted .byn allowlists without ever exposing the vault key, and a row sealed
// with one row key cannot be opened with another's (proven in the tests). The
// derivation is deterministic — same (vaultKey, context) always yields the same
// key — and is independent of the secret VALUE, so updating a value (re-sealed
// under the same row key with a fresh nonce) needs no re-derivation.
//
// Returns ErrBadKey if vaultKey is not VaultKeySize bytes.
func DeriveRowKey(vaultKey, context []byte) ([]byte, error) {
	if len(vaultKey) != VaultKeySize {
		return nil, ErrBadKey
	}
	info := make([]byte, 0, len(rowKeyInfoPrefix)+len(context))
	info = append(info, rowKeyInfoPrefix...)
	info = append(info, context...)

	out := make([]byte, VaultKeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, vaultKey, nil, info), out); err != nil {
		return nil, err
	}
	return out, nil
}
