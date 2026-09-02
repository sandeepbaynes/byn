package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionFileNameFor verifies that fileNameFor is deterministic and
// produces distinct names for distinct (ttyDev, vault) pairs.
func TestSessionFileNameFor(t *testing.T) {
	n1 := fileNameFor(42, "default")
	n2 := fileNameFor(42, "default")
	assert.Equal(t, n1, n2, "same inputs must produce same name")
	assert.Len(t, n1, 32, "sha256[:16] hex = 32 chars")

	n3 := fileNameFor(42, "work")
	assert.NotEqual(t, n1, n3, "different vault → different name")

	n4 := fileNameFor(99, "default")
	assert.NotEqual(t, n1, n4, "different ttyDev → different name")
}

// TestSessionFileNameFor_ZeroTTY ensures ttyDev=0 still produces a stable name
// (used as a fallback, even though save/load no-op on ttyDev=0).
func TestSessionFileNameFor_ZeroTTY(t *testing.T) {
	n := fileNameFor(0, "default")
	assert.Len(t, n, 32)
	assert.Equal(t, n, fileNameFor(0, "default"))
}

// TestSaveAndLoadSessionTokenWithDev round-trips a token through disk.
func TestSaveAndLoadSessionTokenWithDev(t *testing.T) {
	dir := t.TempDir()
	token := []byte("test-session-token-abc123")

	err := saveTokenWithDev(dir, 7, "default", token)
	require.NoError(t, err)

	got := loadTokenWithDev(dir, 7, "default")
	assert.Equal(t, token, got)
}

// TestLoadSessionTokenWithDev_Missing returns nil for missing file.
func TestLoadSessionTokenWithDev_Missing(t *testing.T) {
	dir := t.TempDir()
	got := loadTokenWithDev(dir, 5, "default")
	assert.Nil(t, got)
}

// TestLoadSessionTokenWithDev_ZeroTTY returns nil when ttyDev=0.
func TestLoadSessionTokenWithDev_ZeroTTY(t *testing.T) {
	dir := t.TempDir()
	// Even if we manually write a file for ttyDev=0, load returns nil.
	_ = saveTokenWithDev(dir, 1, "default", []byte("tok"))
	got := loadTokenWithDev(dir, 0, "default")
	assert.Nil(t, got, "ttyDev=0 must always return nil")
}

// TestSaveSessionTokenWithDev_ZeroTTY is a no-op and creates no file.
func TestSaveSessionTokenWithDev_ZeroTTY(t *testing.T) {
	dir := t.TempDir()
	err := saveTokenWithDev(dir, 0, "default", []byte("tok"))
	require.NoError(t, err)
	// sessions dir must not have been created (or is empty).
	entries, _ := os.ReadDir(filepath.Join(dir, "sessions"))
	assert.Empty(t, entries)
}

// TestSaveSessionTokenWithDev_EmptyToken is a no-op.
func TestSaveSessionTokenWithDev_EmptyToken(t *testing.T) {
	dir := t.TempDir()
	err := saveTokenWithDev(dir, 5, "default", nil)
	require.NoError(t, err)
	entries, _ := os.ReadDir(filepath.Join(dir, "sessions"))
	assert.Empty(t, entries)
}

// TestSaveSessionTokenWithDev_FileMode verifies 0600 permissions.
func TestSaveSessionTokenWithDev_FileMode(t *testing.T) {
	dir := t.TempDir()
	err := saveTokenWithDev(dir, 3, "default", []byte("tok"))
	require.NoError(t, err)
	path := filepath.Join(dir, "sessions", fileNameFor(3, "default"))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

// TestDeleteSessionTokenWithDev removes the file and tolerates missing file.
func TestDeleteSessionTokenWithDev(t *testing.T) {
	dir := t.TempDir()
	_ = saveTokenWithDev(dir, 5, "default", []byte("tok"))

	deleteTokenWithDev(dir, 5, "default")
	got := loadTokenWithDev(dir, 5, "default")
	assert.Nil(t, got)

	// Second delete is a no-op.
	deleteTokenWithDev(dir, 5, "default")
}

// TestDeleteSessionTokenWithDev_ZeroTTY is a no-op.
func TestDeleteSessionTokenWithDev_ZeroTTY(t *testing.T) {
	dir := t.TempDir()
	// Should not panic or error.
	deleteTokenWithDev(dir, 0, "default")
}

// TestDeleteAllSessionTokens removes all files in sessions dir.
func TestDeleteAllSessionTokens(t *testing.T) {
	dir := t.TempDir()
	_ = saveTokenWithDev(dir, 1, "default", []byte("tok1"))
	_ = saveTokenWithDev(dir, 2, "default", []byte("tok2"))
	_ = saveTokenWithDev(dir, 3, "work", []byte("tok3"))

	DeleteAllTokens(dir)

	entries, _ := os.ReadDir(filepath.Join(dir, "sessions"))
	assert.Empty(t, entries)
}

// TestDeleteAllSessionTokens_Empty is a no-op on a missing dir.
func TestDeleteAllSessionTokens_Empty(t *testing.T) {
	dir := t.TempDir()
	// sessions dir does not exist; must not panic.
	DeleteAllTokens(dir)
}

// TestVaultSessionKey normalises empty string to "default".
func TestVaultSessionKey(t *testing.T) {
	assert.Equal(t, "default", VaultKey(""))
	assert.Equal(t, "default", VaultKey("default"))
	assert.Equal(t, "work", VaultKey("work"))
	assert.Equal(t, "staging", VaultKey("staging"))
}

// TestSessionDir returns the expected path.
func TestSessionDir(t *testing.T) {
	assert.Equal(t, filepath.Join("/home/user/.byn", "sessions"), Dir("/home/user/.byn"))
}

// TestSaveLoadRoundTrip_MultipleVaults verifies that per-vault files are
// kept separate even when ttyDev is the same.
func TestSaveLoadRoundTrip_MultipleVaults(t *testing.T) {
	dir := t.TempDir()
	const ttyDev int32 = 10
	tokA := []byte("token-for-default")
	tokB := []byte("token-for-work")

	require.NoError(t, saveTokenWithDev(dir, ttyDev, "default", tokA))
	require.NoError(t, saveTokenWithDev(dir, ttyDev, "work", tokB))

	assert.Equal(t, tokA, loadTokenWithDev(dir, ttyDev, "default"))
	assert.Equal(t, tokB, loadTokenWithDev(dir, ttyDev, "work"))
}

// TestSaveOverwrite verifies that saving a new token replaces the old one.
func TestSaveOverwrite(t *testing.T) {
	dir := t.TempDir()
	const ttyDev int32 = 11
	first := []byte("first-token")
	second := []byte("second-token")

	require.NoError(t, saveTokenWithDev(dir, ttyDev, "default", first))
	require.NoError(t, saveTokenWithDev(dir, ttyDev, "default", second))

	got := loadTokenWithDev(dir, ttyDev, "default")
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
