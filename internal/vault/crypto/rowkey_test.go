package crypto

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedKey is a deterministic 32-byte vault key for derivation tests.
func fixedKey() []byte {
	k := make([]byte, VaultKeySize)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// TestDeriveRowKey_Deterministic: same (vaultKey, context) → same key.
func TestDeriveRowKey_Deterministic(t *testing.T) {
	vk := fixedKey()
	ctx := []byte("vault1\x00env_var\x00DB_URL")
	a, err := DeriveRowKey(vk, ctx)
	require.NoError(t, err)
	b, err := DeriveRowKey(vk, ctx)
	require.NoError(t, err)
	assert.Equal(t, a, b, "derivation must be deterministic")
	assert.Len(t, a, VaultKeySize)
}

// TestDeriveRowKey_DistinctPerContext: different rows get different keys, and a
// row key never equals the vault key (domain separation).
func TestDeriveRowKey_DistinctPerContext(t *testing.T) {
	vk := fixedKey()
	k1, err := DeriveRowKey(vk, []byte("v\x00env_var\x00A"))
	require.NoError(t, err)
	k2, err := DeriveRowKey(vk, []byte("v\x00env_var\x00B"))
	require.NoError(t, err)
	assert.NotEqual(t, k1, k2, "distinct contexts must yield distinct keys")
	assert.NotEqual(t, vk, k1, "row key must not equal the vault key")
}

// TestDeriveRowKey_DistinctPerVaultKey: rotating the vault key changes every
// row key.
func TestDeriveRowKey_DistinctPerVaultKey(t *testing.T) {
	ctx := []byte("v\x00env_var\x00A")
	k1, err := DeriveRowKey(fixedKey(), ctx)
	require.NoError(t, err)
	vk2, err := NewVaultKey()
	require.NoError(t, err)
	k2, err := DeriveRowKey(vk2, ctx)
	require.NoError(t, err)
	assert.NotEqual(t, k1, k2)
}

// TestDeriveRowKey_BadKey: a wrong-size vault key is rejected.
func TestDeriveRowKey_BadKey(t *testing.T) {
	_, err := DeriveRowKey([]byte("short"), []byte("ctx"))
	require.ErrorIs(t, err, ErrBadKey)
	_, err = DeriveRowKey(nil, []byte("ctx"))
	require.ErrorIs(t, err, ErrBadKey)
}

// TestDeriveRowKey_RoundTrip: a row sealed under its row key opens under the
// same row key — the daemon can decrypt with ONLY the row key (no vault key).
func TestDeriveRowKey_RoundTrip(t *testing.T) {
	vk := fixedKey()
	ctx := []byte("v\x00env_var\x00DB_URL")
	aad := []byte("v\x00env_var\x00DB_URL")
	krow, err := DeriveRowKey(vk, ctx)
	require.NoError(t, err)

	ct, err := EncryptWithAAD(krow, []byte("postgres://secret"), aad)
	require.NoError(t, err)
	pt, err := DecryptWithAAD(krow, ct, aad)
	require.NoError(t, err)
	assert.Equal(t, "postgres://secret", string(pt))
}

// TestDeriveRowKey_PerRowIsolation: a row sealed with row A's key CANNOT be
// opened with row B's key. This is the property the capability model depends
// on — handing out one row's key never unlocks another row.
func TestDeriveRowKey_PerRowIsolation(t *testing.T) {
	vk := fixedKey()
	keyA, err := DeriveRowKey(vk, []byte("v\x00env_var\x00A"))
	require.NoError(t, err)
	keyB, err := DeriveRowKey(vk, []byte("v\x00env_var\x00B"))
	require.NoError(t, err)

	aadA := []byte("v\x00env_var\x00A")
	ctA, err := EncryptWithAAD(keyA, []byte("A-secret"), aadA)
	require.NoError(t, err)

	_, err = DecryptWithAAD(keyB, ctA, aadA)
	require.Error(t, err, "row B's key must not open row A's ciphertext")
	assert.True(t, errors.Is(err, ErrTampered), "cross-row decrypt should look like tampering, got %v", err)
}

// TestDeriveRowKey_ValueUpdateNoRederive: re-sealing the SAME row with a new
// value uses the same row key (fresh nonce) and decrypts fine — so updating a
// secret's value needs no re-trust / re-derivation of the capability.
func TestDeriveRowKey_ValueUpdateNoRederive(t *testing.T) {
	vk := fixedKey()
	ctx := []byte("v\x00env_var\x00TOKEN")
	aad := []byte("v\x00env_var\x00TOKEN")
	krow, err := DeriveRowKey(vk, ctx)
	require.NoError(t, err)

	ctOld, err := EncryptWithAAD(krow, []byte("v1"), aad)
	require.NoError(t, err)
	ctNew, err := EncryptWithAAD(krow, []byte("v2-rotated"), aad)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(ctOld, ctNew), "re-seal should use a fresh nonce")

	// The SAME row key (captured once at trust time) decrypts the updated value.
	pt, err := DecryptWithAAD(krow, ctNew, aad)
	require.NoError(t, err)
	assert.Equal(t, "v2-rotated", string(pt))
}
