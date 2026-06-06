// Package crypto contains the vault's symmetric primitives:
//
//   - Argon2id-based password wrapping of the 32-byte vault key
//     (functions Wrap, Unwrap)
//   - XChaCha20-Poly1305 row encryption keyed by the vault key
//     (functions Encrypt, Decrypt)
//
// Why XChaCha20-Poly1305 and not the age file format: age is a file
// container with header framing designed for at-rest blobs. For
// row-level secret values we want the smallest possible ciphertext
// with no header, no recipient framing, and a single AEAD. The
// primitive is the same one age uses underneath (ChaCha20-Poly1305,
// extended-nonce variant), so the security goal — "modern AEAD keyed
// by the vault key" — is met. The age file format will be reintroduced
// in Phase 6 for vault export/import.
//
// Argon2id parameters can be tuned per install. Defaults aim for ~1s
// on a modern laptop (Argon2 RFC 9106 recommended profile). Persisted
// alongside the ciphertext so a wrapped key can always be unwrapped
// even if the daemon's defaults change.
package crypto
