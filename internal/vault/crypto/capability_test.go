package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fingerprint() []byte { return []byte("machine-fingerprint-bytes-0001") }

// TestDeriveCapKey_Deterministic: same fingerprint → same K_cap, 32 bytes.
func TestDeriveCapKey_Deterministic(t *testing.T) {
	a, err := DeriveCapKey(fingerprint())
	require.NoError(t, err)
	b, err := DeriveCapKey(fingerprint())
	require.NoError(t, err)
	assert.Equal(t, a, b)
	assert.Len(t, a, VaultKeySize)
	assert.NotEqual(t, fingerprint(), a, "K_cap must not equal the fingerprint")
}

// TestDeriveCapKey_DistinctPerMachine: different fingerprints → different K_cap.
func TestDeriveCapKey_DistinctPerMachine(t *testing.T) {
	a, err := DeriveCapKey(fingerprint())
	require.NoError(t, err)
	b, err := DeriveCapKey([]byte("a-different-machine-fingerprint"))
	require.NoError(t, err)
	assert.NotEqual(t, a, b)
}

// TestDeriveCapKey_EmptyFingerprint: empty fingerprint is rejected (callers must
// fall back to the password path).
func TestDeriveCapKey_EmptyFingerprint(t *testing.T) {
	_, err := DeriveCapKey(nil)
	require.ErrorIs(t, err, ErrBadKey)
	_, err = DeriveCapKey([]byte{})
	require.ErrorIs(t, err, ErrBadKey)
}

// TestCapability_RoundTrip: the per-row keys survive seal→open under K_cap.
func TestCapability_RoundTrip(t *testing.T) {
	capKey, err := DeriveCapKey(fingerprint())
	require.NoError(t, err)
	in := map[string][]byte{
		"DB_URL":  bytesOf(0xAA, VaultKeySize),
		"API_KEY": bytesOf(0xBB, VaultKeySize),
	}
	blob, err := SealCapability(capKey, in)
	require.NoError(t, err)
	out, err := OpenCapability(capKey, blob)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

// TestCapability_WrongCapKey: a capability sealed on one machine cannot be
// opened with another machine's K_cap.
func TestCapability_WrongCapKey(t *testing.T) {
	capA, err := DeriveCapKey(fingerprint())
	require.NoError(t, err)
	capB, err := DeriveCapKey([]byte("other-machine-fingerprint-xyz"))
	require.NoError(t, err)

	blob, err := SealCapability(capA, map[string][]byte{"X": bytesOf(1, VaultKeySize)})
	require.NoError(t, err)
	_, err = OpenCapability(capB, blob)
	require.ErrorIs(t, err, ErrTampered)
}

// TestCapability_TamperedBlob: a flipped byte fails open.
func TestCapability_TamperedBlob(t *testing.T) {
	capKey, err := DeriveCapKey(fingerprint())
	require.NoError(t, err)
	blob, err := SealCapability(capKey, map[string][]byte{"X": bytesOf(1, VaultKeySize)})
	require.NoError(t, err)
	blob[len(blob)-1] ^= 0xFF
	_, err = OpenCapability(capKey, blob)
	require.Error(t, err)
}

// TestCapability_BadKeySize: a wrong-size K_cap is rejected on both seal+open.
func TestCapability_BadKeySize(t *testing.T) {
	_, err := SealCapability([]byte("short"), map[string][]byte{})
	require.ErrorIs(t, err, ErrBadKey)
	_, err = OpenCapability([]byte("short"), []byte("blob"))
	require.ErrorIs(t, err, ErrBadKey)
}

// TestCapability_EndToEnd proves the whole mechanism: a row key recovered FROM
// the capability (no vault key in sight) decrypts a row that was sealed with
// that row key. This is exactly what trusted exec does after a reboot.
func TestCapability_EndToEnd(t *testing.T) {
	vk := fixedKey() // stands in for the vault key, used ONLY at "trust time"
	rowCtx := []byte("v\x00env_var\x00DB_URL")
	krow, err := DeriveRowKey(vk, rowCtx)
	require.NoError(t, err)

	// Trust time: seal the row's value with its row key, and stash the row key
	// in a capability under K_cap.
	ct, err := EncryptWithAAD(krow, []byte("postgres://prod"), rowCtx)
	require.NoError(t, err)
	capKey, err := DeriveCapKey(fingerprint())
	require.NoError(t, err)
	blob, err := SealCapability(capKey, map[string][]byte{"DB_URL": krow})
	require.NoError(t, err)

	// Exec time (cold — no vault key): recover the row key from the capability
	// and decrypt the row.
	recovered, err := OpenCapability(capKey, blob)
	require.NoError(t, err)
	pt, err := DecryptWithAAD(recovered["DB_URL"], ct, rowCtx)
	require.NoError(t, err)
	assert.Equal(t, "postgres://prod", string(pt))
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
