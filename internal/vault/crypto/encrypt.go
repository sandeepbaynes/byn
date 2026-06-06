package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptFormatVersion is the on-disk row-encryption format version.
// Independent of WrapFormatVersion; bump on incompatible changes.
const EncryptFormatVersion uint8 = 1

// Encrypt seals plaintext with the vault key. Output layout:
//
//	[0]                version uint8
//	[1..1+nonceSize)   24-byte XChaCha20 nonce
//	[1+nonceSize..]    ChaCha20-Poly1305 ciphertext+tag
//
// AAD binds the version byte to the ciphertext. Use EncryptWithAAD when
// you also need to bind external context (e.g., the entry's
// vault_id || kind || name).
func Encrypt(vaultKey, plaintext []byte) ([]byte, error) {
	return EncryptWithAAD(vaultKey, plaintext, nil)
}

// EncryptWithAAD is Encrypt with an additional caller-supplied AAD that
// is bound to the ciphertext. The same userAAD must be passed to
// DecryptWithAAD; otherwise decryption fails as if the ciphertext was
// tampered. Used by the vault layer to bind entry ciphertexts to
// (vault_id, kind, name) — preventing within-vault row swaps.
//
// The effective AAD is [version || userAAD], so the version byte
// continues to be authenticated even when userAAD is non-nil.
func EncryptWithAAD(vaultKey, plaintext, userAAD []byte) ([]byte, error) {
	if len(vaultKey) != VaultKeySize {
		return nil, ErrBadKey
	}
	aead, err := chacha20poly1305.NewX(vaultKey)
	if err != nil {
		return nil, fmt.Errorf("vault/crypto: aead init: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault/crypto: rand: %w", err)
	}
	aad := buildAAD(userAAD)
	out := make([]byte, 1+len(nonce), 1+len(nonce)+len(plaintext)+aead.Overhead())
	out[0] = EncryptFormatVersion
	copy(out[1:], nonce)
	out = aead.Seal(out, nonce, plaintext, aad)
	return out, nil
}

// Decrypt reverses Encrypt. Returns ErrTampered for any AEAD or format
// failure.
func Decrypt(vaultKey, ciphertext []byte) ([]byte, error) {
	return DecryptWithAAD(vaultKey, ciphertext, nil)
}

// DecryptWithAAD reverses EncryptWithAAD. The userAAD passed here must
// match what was bound at encrypt time, byte-for-byte.
func DecryptWithAAD(vaultKey, ciphertext, userAAD []byte) ([]byte, error) {
	if len(vaultKey) != VaultKeySize {
		return nil, ErrBadKey
	}
	if len(ciphertext) < 1+chacha20poly1305.NonceSizeX {
		return nil, ErrTampered
	}
	if ciphertext[0] != EncryptFormatVersion {
		return nil, ErrTampered
	}
	aead, err := chacha20poly1305.NewX(vaultKey)
	if err != nil {
		return nil, fmt.Errorf("vault/crypto: aead init: %w", err)
	}
	nonce := ciphertext[1 : 1+aead.NonceSize()]
	body := ciphertext[1+aead.NonceSize():]
	aad := buildAAD(userAAD)
	plain, err := aead.Open(nil, nonce, body, aad)
	if err != nil {
		return nil, ErrTampered
	}
	return plain, nil
}

// buildAAD packs the version byte with any caller-supplied AAD. We
// always include the version byte first so format-version tampering is
// rejected even when userAAD is empty.
func buildAAD(userAAD []byte) []byte {
	if len(userAAD) == 0 {
		return []byte{EncryptFormatVersion}
	}
	aad := make([]byte, 1+len(userAAD))
	aad[0] = EncryptFormatVersion
	copy(aad[1:], userAAD)
	return aad
}
