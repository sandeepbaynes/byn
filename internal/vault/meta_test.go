package vault

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateVaultName(t *testing.T) {
	good := []string{"default", "acme-prod", "personal", "x", "a0", "a1-b2_c3", strings.Repeat("a", 63)}
	for _, n := range good {
		if err := ValidateVaultName(n); err != nil {
			t.Errorf("ValidateVaultName(%q) = %v, want nil", n, err)
		}
	}
	bad := []string{
		"",
		"-leading-dash",
		"_leading-underscore",
		"UPPER",
		"with space",
		"with/slash",
		"with.dot",
		strings.Repeat("a", 64), // one over the cap
	}
	for _, n := range bad {
		if err := ValidateVaultName(n); !errors.Is(err, ErrBadVaultName) {
			t.Errorf("ValidateVaultName(%q) = %v, want ErrBadVaultName", n, err)
		}
	}
}

func TestInit_WritesMetaJSON(t *testing.T) {
	dir := t.TempDir()
	st, err := Init(context.Background(), dir, DefaultVaultName, []byte("pw"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer st.Close()

	vdir := Dir(dir, DefaultVaultName)
	metaPath := filepath.Join(vdir, MetaFilename)
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var m Meta
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.SchemaVersion != MetaFormatVersion {
		t.Errorf("SchemaVersion = %d, want %d", m.SchemaVersion, MetaFormatVersion)
	}
	if m.Name != DefaultVaultName {
		t.Errorf("Name = %q, want %q", m.Name, DefaultVaultName)
	}
	if m.FingerprintAlg != FingerprintAlg {
		t.Errorf("FingerprintAlg = %q, want %q", m.FingerprintAlg, FingerprintAlg)
	}
	if len(m.VaultID) < 32 {
		t.Errorf("VaultID looks bogus: %q", m.VaultID)
	}
	if len(m.Fingerprint) != 64 {
		t.Errorf("Fingerprint should be 64-hex SHA-256, got %d chars: %q", len(m.Fingerprint), m.Fingerprint)
	}
	if m.CreatedAt <= 0 {
		t.Errorf("CreatedAt = %d, want positive", m.CreatedAt)
	}
}

func TestOpen_FingerprintMismatch(t *testing.T) {
	dir := t.TempDir()
	st, err := Init(context.Background(), dir, DefaultVaultName, []byte("pw"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	st.Close()

	// Swap wrapped.key contents (length-preserving so the partial-state
	// branch doesn't trip first). The fingerprint check should refuse.
	vdir := Dir(dir, DefaultVaultName)
	wp := filepath.Join(vdir, wrappedFilename)
	orig, err := os.ReadFile(wp)
	if err != nil {
		t.Fatalf("read wrapped: %v", err)
	}
	bogus := make([]byte, len(orig))
	for i := range bogus {
		bogus[i] = ^orig[i] // bit-invert; same length, different content
	}
	if err := os.WriteFile(wp, bogus, 0o600); err != nil {
		t.Fatalf("write wrapped: %v", err)
	}
	if _, err := Open(context.Background(), dir, DefaultVaultName); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("Open with mismatched fingerprint: err = %v, want ErrFingerprintMismatch", err)
	}
}

func TestOpen_RejectsUnknownMetaFields(t *testing.T) {
	dir := t.TempDir()
	st, err := Init(context.Background(), dir, DefaultVaultName, []byte("pw"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	st.Close()

	vdir := Dir(dir, DefaultVaultName)
	metaPath := filepath.Join(vdir, MetaFilename)
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	// Inject an unknown key.
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m["evil_extra"] = "should-be-rejected"
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(metaPath, tampered, 0o600); err != nil {
		t.Fatalf("write meta: %v", err)
	}
	_, err = Open(context.Background(), dir, DefaultVaultName)
	if err == nil || !strings.Contains(err.Error(), "evil_extra") {
		t.Fatalf("Open with unknown meta field: err = %v, want error mentioning the field", err)
	}
}

func TestInit_RejectsBadVaultName(t *testing.T) {
	dir := t.TempDir()
	_, err := Init(context.Background(), dir, "BadName", []byte("pw"))
	if !errors.Is(err, ErrBadVaultName) {
		t.Fatalf("Init bad name: err = %v, want ErrBadVaultName", err)
	}
}

func TestOpen_RejectsBadVaultName(t *testing.T) {
	_, err := Open(context.Background(), t.TempDir(), "BadName")
	if !errors.Is(err, ErrBadVaultName) {
		t.Fatalf("Open bad name: err = %v, want ErrBadVaultName", err)
	}
}

func TestDir_Shape(t *testing.T) {
	got := Dir("/root", "myvault")
	want := filepath.Join("/root", "vaults", "myvault")
	if got != want {
		t.Errorf("Dir = %q, want %q", got, want)
	}
}
