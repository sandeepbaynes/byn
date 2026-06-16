package crypto

import (
	"crypto/sha256"
	"encoding/json"
	"io"

	"golang.org/x/crypto/hkdf"
)

// capKeyInfo domain-separates the exec-capability wrapping key (K_cap) from
// every other key derived from the machine fingerprint (e.g. the trust-store
// fp-MAC). Bump the suffix on any incompatible change.
const capKeyInfo = "byn/exec-cap-key/v1\x00"

// capAAD binds the capability blob format to its ciphertext.
var capAAD = []byte("byn/exec-cap/v1")

// DeriveCapKey derives K_cap — the key that wraps a trusted .byn's stored
// per-row keys — from the machine fingerprint via HKDF-SHA256.
//
// K_cap is the linchpin of the "survives restart, no password" property: the
// machine fingerprint is hardware-derived and recomputed at daemon start with
// no password, so the daemon can unwrap a stored capability cold. The
// fingerprint must be non-empty — callers handle the "machine id unavailable"
// fallback (require the master password) BEFORE reaching here.
func DeriveCapKey(machineFingerprint []byte) ([]byte, error) {
	if len(machineFingerprint) == 0 {
		return nil, ErrBadKey
	}
	out := make([]byte, VaultKeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, machineFingerprint, nil, []byte(capKeyInfo)), out); err != nil {
		return nil, err
	}
	return out, nil
}

// SealCapability wraps the per-row keys for a trusted .byn's allowlisted vars
// (name → K_row) under K_cap. The resulting blob is persisted on disk in the
// trust record; OpenCapability with the same K_cap recovers the keys at exec
// time. Returns ErrBadKey if capKey is the wrong size.
func SealCapability(capKey []byte, rowKeys map[string][]byte) ([]byte, error) {
	if len(capKey) != VaultKeySize {
		return nil, ErrBadKey
	}
	plain, err := json.Marshal(rowKeys) // []byte values marshal as base64
	if err != nil {
		return nil, err
	}
	return EncryptWithAAD(capKey, plain, capAAD)
}

// OpenCapability reverses SealCapability. Returns ErrTampered when K_cap is
// wrong or the blob was corrupted (indistinguishable by design), and ErrBadKey
// for a wrong-size capKey.
func OpenCapability(capKey, blob []byte) (map[string][]byte, error) {
	if len(capKey) != VaultKeySize {
		return nil, ErrBadKey
	}
	plain, err := DecryptWithAAD(capKey, blob, capAAD)
	if err != nil {
		return nil, err
	}
	var m map[string][]byte
	if err := json.Unmarshal(plain, &m); err != nil {
		return nil, ErrTampered
	}
	return m, nil
}
