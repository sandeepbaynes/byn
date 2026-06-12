package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionFileNameFor verifies that sessionFileNameFor is deterministic and
// produces distinct names for distinct (ttyDev, vault) pairs.
func TestSessionFileNameFor(t *testing.T) {
	n1 := sessionFileNameFor(42, "default")
	n2 := sessionFileNameFor(42, "default")
	assert.Equal(t, n1, n2, "same inputs must produce same name")
	assert.Len(t, n1, 32, "sha256[:16] hex = 32 chars")

	n3 := sessionFileNameFor(42, "work")
	assert.NotEqual(t, n1, n3, "different vault → different name")

	n4 := sessionFileNameFor(99, "default")
	assert.NotEqual(t, n1, n4, "different ttyDev → different name")
}

// TestSessionFileNameFor_ZeroTTY ensures ttyDev=0 still produces a stable name
// (used as a fallback, even though save/load no-op on ttyDev=0).
func TestSessionFileNameFor_ZeroTTY(t *testing.T) {
	n := sessionFileNameFor(0, "default")
	assert.Len(t, n, 32)
	assert.Equal(t, n, sessionFileNameFor(0, "default"))
}

// TestSaveAndLoadSessionTokenWithDev round-trips a token through disk.
func TestSaveAndLoadSessionTokenWithDev(t *testing.T) {
	dir := t.TempDir()
	token := []byte("test-session-token-abc123")

	err := saveSessionTokenWithDev(dir, 7, "default", token)
	require.NoError(t, err)

	got := loadSessionTokenWithDev(dir, 7, "default")
	assert.Equal(t, token, got)
}

// TestLoadSessionTokenWithDev_Missing returns nil for missing file.
func TestLoadSessionTokenWithDev_Missing(t *testing.T) {
	dir := t.TempDir()
	got := loadSessionTokenWithDev(dir, 5, "default")
	assert.Nil(t, got)
}

// TestLoadSessionTokenWithDev_ZeroTTY returns nil when ttyDev=0.
func TestLoadSessionTokenWithDev_ZeroTTY(t *testing.T) {
	dir := t.TempDir()
	// Even if we manually write a file for ttyDev=0, load returns nil.
	_ = saveSessionTokenWithDev(dir, 1, "default", []byte("tok"))
	got := loadSessionTokenWithDev(dir, 0, "default")
	assert.Nil(t, got, "ttyDev=0 must always return nil")
}

// TestSaveSessionTokenWithDev_ZeroTTY is a no-op and creates no file.
func TestSaveSessionTokenWithDev_ZeroTTY(t *testing.T) {
	dir := t.TempDir()
	err := saveSessionTokenWithDev(dir, 0, "default", []byte("tok"))
	require.NoError(t, err)
	// sessions dir must not have been created (or is empty).
	entries, _ := os.ReadDir(filepath.Join(dir, "sessions"))
	assert.Empty(t, entries)
}

// TestSaveSessionTokenWithDev_EmptyToken is a no-op.
func TestSaveSessionTokenWithDev_EmptyToken(t *testing.T) {
	dir := t.TempDir()
	err := saveSessionTokenWithDev(dir, 5, "default", nil)
	require.NoError(t, err)
	entries, _ := os.ReadDir(filepath.Join(dir, "sessions"))
	assert.Empty(t, entries)
}

// TestSaveSessionTokenWithDev_FileMode verifies 0600 permissions.
func TestSaveSessionTokenWithDev_FileMode(t *testing.T) {
	dir := t.TempDir()
	err := saveSessionTokenWithDev(dir, 3, "default", []byte("tok"))
	require.NoError(t, err)
	path := filepath.Join(dir, "sessions", sessionFileNameFor(3, "default"))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

// TestDeleteSessionTokenWithDev removes the file and tolerates missing file.
func TestDeleteSessionTokenWithDev(t *testing.T) {
	dir := t.TempDir()
	_ = saveSessionTokenWithDev(dir, 5, "default", []byte("tok"))

	deleteSessionTokenWithDev(dir, 5, "default")
	got := loadSessionTokenWithDev(dir, 5, "default")
	assert.Nil(t, got)

	// Second delete is a no-op.
	deleteSessionTokenWithDev(dir, 5, "default")
}

// TestDeleteSessionTokenWithDev_ZeroTTY is a no-op.
func TestDeleteSessionTokenWithDev_ZeroTTY(t *testing.T) {
	dir := t.TempDir()
	// Should not panic or error.
	deleteSessionTokenWithDev(dir, 0, "default")
}

// TestDeleteAllSessionTokens removes all files in sessions dir.
func TestDeleteAllSessionTokens(t *testing.T) {
	dir := t.TempDir()
	_ = saveSessionTokenWithDev(dir, 1, "default", []byte("tok1"))
	_ = saveSessionTokenWithDev(dir, 2, "default", []byte("tok2"))
	_ = saveSessionTokenWithDev(dir, 3, "work", []byte("tok3"))

	deleteAllSessionTokens(dir)

	entries, _ := os.ReadDir(filepath.Join(dir, "sessions"))
	assert.Empty(t, entries)
}

// TestDeleteAllSessionTokens_Empty is a no-op on a missing dir.
func TestDeleteAllSessionTokens_Empty(t *testing.T) {
	dir := t.TempDir()
	// sessions dir does not exist; must not panic.
	deleteAllSessionTokens(dir)
}

// TestVaultSessionKey normalises empty string to "default".
func TestVaultSessionKey(t *testing.T) {
	assert.Equal(t, "default", vaultSessionKey(""))
	assert.Equal(t, "default", vaultSessionKey("default"))
	assert.Equal(t, "work", vaultSessionKey("work"))
	assert.Equal(t, "staging", vaultSessionKey("staging"))
}

// TestSessionDir returns the expected path.
func TestSessionDir(t *testing.T) {
	assert.Equal(t, filepath.Join("/home/user/.byn", "sessions"), sessionDir("/home/user/.byn"))
}

// TestSaveLoadRoundTrip_MultipleVaults verifies that per-vault files are
// kept separate even when ttyDev is the same.
func TestSaveLoadRoundTrip_MultipleVaults(t *testing.T) {
	dir := t.TempDir()
	const ttyDev int32 = 10
	tokA := []byte("token-for-default")
	tokB := []byte("token-for-work")

	require.NoError(t, saveSessionTokenWithDev(dir, ttyDev, "default", tokA))
	require.NoError(t, saveSessionTokenWithDev(dir, ttyDev, "work", tokB))

	assert.Equal(t, tokA, loadSessionTokenWithDev(dir, ttyDev, "default"))
	assert.Equal(t, tokB, loadSessionTokenWithDev(dir, ttyDev, "work"))
}

// TestSaveOverwrite verifies that saving a new token replaces the old one.
func TestSaveOverwrite(t *testing.T) {
	dir := t.TempDir()
	const ttyDev int32 = 11
	first := []byte("first-token")
	second := []byte("second-token")

	require.NoError(t, saveSessionTokenWithDev(dir, ttyDev, "default", first))
	require.NoError(t, saveSessionTokenWithDev(dir, ttyDev, "default", second))

	got := loadSessionTokenWithDev(dir, ttyDev, "default")
	assert.Equal(t, second, got)
}

// TestTTYRdev_DoesNotPanic verifies that ttyRdev() does not panic and returns
// a value (0 or a device number — both are valid depending on whether the test
// runner has a controlling terminal).
func TestTTYRdev_DoesNotPanic(t *testing.T) {
	dev := ttyRdev()
	// 0 is valid (no controlling terminal in CI); any int32 is valid.
	_ = dev
}
