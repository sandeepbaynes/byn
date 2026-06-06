package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"
)

// Per-vault directory layout under the root:
//
//	<root>/vaults/<vaultName>/vault.db
//	<root>/vaults/<vaultName>/wrapped.key
//	<root>/vaults/<vaultName>/meta.json
const (
	VaultsSubdir     = "vaults"
	MetaFilename     = "meta.json"
	DefaultVaultName = "default"

	// MetaFormatVersion is the on-disk schema of meta.json. Bump on
	// incompatible changes; never reuse a value.
	MetaFormatVersion = 1

	// FingerprintAlg labels the hash function used for the wrapped-key
	// fingerprint. Lets us migrate to a stronger hash without
	// re-keying.
	FingerprintAlg = "sha256-v1"
)

// vaultNameRegex enforces the lowercase, no-leading-underscore policy
// agreed during design review. Reject-with-suggestion happens at the
// CLI layer; here we hard-refuse so the daemon never persists an
// invalid name.
var vaultNameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ErrBadVaultName is returned when a vault name violates the naming
// rules. Lowercase only, 1–63 chars, [a-z0-9_-], no leading dash or
// underscore.
var ErrBadVaultName = errors.New("vault: invalid vault name (lowercase letters/digits, _ or - after first char, max 63 chars)")

// ErrFingerprintMismatch is returned when meta.json's recorded
// wrapped-key fingerprint doesn't match the actual wrapped.key on
// disk. Indicates tampering, partial swap, or an incomplete restore.
var ErrFingerprintMismatch = errors.New("vault: wrapped-key fingerprint does not match meta.json (possible tampering or partial restore)")

// ValidateVaultName returns nil if name is acceptable. Callers should
// validate before creating a vault on disk.
func ValidateVaultName(name string) error {
	if !vaultNameRegex.MatchString(name) {
		return ErrBadVaultName
	}
	return nil
}

// Meta is the on-disk content of meta.json. Strict JSON: unknown
// keys are rejected on read so an attacker can't add fields the
// daemon ignores.
type Meta struct {
	SchemaVersion  int    `json:"schema_version"`
	Name           string `json:"name"`
	VaultID        string `json:"vault_id"`
	CreatedAt      int64  `json:"created_at"`
	Fingerprint    string `json:"fingerprint"`
	FingerprintAlg string `json:"fingerprint_alg"`
}

// writeMeta atomically writes m to path with mode 0600.
func writeMeta(path string, m Meta) error {
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("vault: marshal meta: %w", err)
	}
	// Append a trailing newline so the file reads cleanly when
	// inspected with cat / less.
	body = append(body, '\n')
	return writeFileAtomic(path, body, 0o600)
}

// readMeta reads and validates meta.json from path. Returns
// ErrFingerprintMismatch if the recorded fingerprint doesn't match
// the wrapped-key bytes the caller passes in.
func readMeta(path string, wrappedKeyBytes []byte) (Meta, error) {
	var m Meta
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from store config
	if err != nil {
		return m, fmt.Errorf("vault: read meta: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("vault: decode meta: %w", err)
	}
	if m.SchemaVersion != MetaFormatVersion {
		return m, fmt.Errorf("vault: meta schema_version=%d, this build expects %d", m.SchemaVersion, MetaFormatVersion)
	}
	if m.FingerprintAlg != FingerprintAlg {
		return m, fmt.Errorf("vault: meta fingerprint_alg=%q, this build expects %q", m.FingerprintAlg, FingerprintAlg)
	}
	if m.Fingerprint != computeFingerprint(wrappedKeyBytes) {
		return m, ErrFingerprintMismatch
	}
	return m, nil
}

// computeFingerprint hashes wrapped-key bytes for tamper detection.
// Plain SHA-256; not keyed because there's no global key available
// before unlock. Same hash function on every machine, so a vault
// backup verifies anywhere.
func computeFingerprint(wrappedKeyBytes []byte) string {
	sum := sha256.Sum256(wrappedKeyBytes)
	return hex.EncodeToString(sum[:])
}

// newVaultID returns a randomly generated UUID v4 string. The daemon
// stores it in meta.json and (after Slice 2) also in the DB meta
// table as part of the AEAD AAD on new writes.
func newVaultID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// RFC 4122 v4: version + variant bits.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// nowUnix returns the current time as an int64 unix timestamp.
// Wrapped in a function so tests can stub it later if needed.
var nowUnix = func() int64 { return time.Now().Unix() }
