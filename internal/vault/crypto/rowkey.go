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

// Domain separators for the two-level scheme. envKeyInfoPrefix derives a scope
// key from the vault key; rowFromEnvInfoPrefix derives a row key from that
// scope key. Distinct prefixes keep either level from ever colliding with the
// other or with the flat v1 derivation above.
const (
	envKeyInfoPrefix     = "byn/env-key/v1\x00"
	rowFromEnvInfoPrefix = "byn/row-key/v2\x00"
)

// DeriveEnvKey derives the key covering one (project, env) scope from the vault
// key. scopeContext is the caller's stable scope identity — vaultID‖projectID‖
// envID — and must be built the same way every time.
//
// This is the level that makes a trusted .byn keep working as a project grows:
// a grant seals K_env once, and the daemon can then derive the row key for any
// entry in that scope, INCLUDING entries created after the grant. The flat
// DeriveRowKey scheme could only hand out keys for rows that already existed,
// which is why adding a variable used to demand a fresh re-trust.
//
// Returns ErrBadKey if vaultKey is not VaultKeySize bytes.
func DeriveEnvKey(vaultKey, scopeContext []byte) ([]byte, error) {
	if len(vaultKey) != VaultKeySize {
		return nil, ErrBadKey
	}
	return expand(vaultKey, envKeyInfoPrefix, scopeContext)
}

// DeriveRowKeyFromEnvKey derives a single row's key from the scope key returned
// by DeriveEnvKey. rowContext is the row's identity WITHIN the scope (kind‖name)
// — the scope is already bound by envKey itself, so repeating it here would be
// redundant.
//
// Holding envKey therefore grants exactly one scope: it cannot open rows in
// another project or env, because those derive from a different envKey.
func DeriveRowKeyFromEnvKey(envKey, rowContext []byte) ([]byte, error) {
	if len(envKey) != VaultKeySize {
		return nil, ErrBadKey
	}
	return expand(envKey, rowFromEnvInfoPrefix, rowContext)
}

func expand(secret []byte, prefix string, context []byte) ([]byte, error) {
	info := make([]byte, 0, len(prefix)+len(context))
	info = append(info, prefix...)
	info = append(info, context...)

	out := make([]byte, VaultKeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, nil, info), out); err != nil {
		return nil, err
	}
	return out, nil
}

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
	return expand(vaultKey, rowKeyInfoPrefix, context)
}

// authoredKeyInfoPrefix domain-separates the self-authored scope key from the
// ordinary scope key. Deriving both from the same vault key with different info
// means holding one can never yield the other.
const (
	authoredKeyInfoPrefix     = "byn/authored-key/v1\x00"
	rowFromAuthoredInfoPrefix = "byn/row-key/authored/v1\x00"
)

// DeriveAuthoredKey derives the key covering entries a caller creates in one
// (project, env) scope while the vault is LOCKED.
//
// A locked vault holds no vault key, so it cannot encrypt anything — which made
// `byn put` impossible without a password and left one honest answer for an
// agent working alone: leave the vault unlocked. That is worse than the problem.
// An unlocked vault exposes every secret in it; this key exposes only what the
// agent itself writes.
//
// It is sealed into a trusted .byn's exec capability under the machine key, so
// a locked daemon can both write new entries and read them back. It cannot open
// anything that already existed: those rows derive from K_env, and no amount of
// K_auth yields it. So the containment is exactly the useful one — the master
// password still guards every secret that was in the vault before the agent
// started, and the machine guards what the agent adds.
//
// scopeContext is the caller's stable scope identity — vaultID‖projectID‖envID —
// and must be built the same way every time.
//
// Returns ErrBadKey if vaultKey is not VaultKeySize bytes.
func DeriveAuthoredKey(vaultKey, scopeContext []byte) ([]byte, error) {
	if len(vaultKey) != VaultKeySize {
		return nil, ErrBadKey
	}
	return expand(vaultKey, authoredKeyInfoPrefix, scopeContext)
}

// DeriveRowKeyFromAuthoredKey derives one entry's key from the self-authored
// scope key, mirroring DeriveRowKeyFromEnvKey one level down.
func DeriveRowKeyFromAuthoredKey(authoredKey, rowContext []byte) ([]byte, error) {
	if len(authoredKey) != VaultKeySize {
		return nil, ErrBadKey
	}
	return expand(authoredKey, rowFromAuthoredInfoPrefix, rowContext)
}
