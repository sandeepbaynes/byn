package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// VaultKeySize is the size of the unwrapped vault key in bytes.
const VaultKeySize = 32

// WrapFormatVersion is the on-disk wrapped-key format version. Bump on
// incompatible changes; never reuse a value.
const WrapFormatVersion uint8 = 1

// SaltSize is the Argon2id salt size in bytes. 16 bytes per the
// Argon2 RFC recommendation; using 32 to match the wider state.
const SaltSize = 32

// Argon2Params is the tunable cost profile for Argon2id key
// derivation. Persisted alongside the ciphertext so changing defaults
// doesn't invalidate existing wraps.
//
// Defaults (DefaultArgon2Params) target ~1s on a modern laptop:
// time=2, memory=64MiB, threads=4. See RFC 9106 §4 for the rationale
// behind the i+d hybrid (Argon2id).
type Argon2Params struct {
	Time    uint32 // iterations
	Memory  uint32 // KiB
	Threads uint8
}

// DefaultArgon2Params is the cost profile used when no override is
// supplied. Conservative for laptops, mild for servers.
var DefaultArgon2Params = Argon2Params{
	Time:    2,
	Memory:  64 * 1024,
	Threads: 4,
}

// TestArgon2Params is the minimum cost profile that still satisfies
// validateParams (Time>=1, Memory>=8MiB, Threads>=1). It exists ONLY so
// tests that perform real vault init/unlock don't pay the ~1s/op
// production Argon2 cost; under -race on slow CI runners the cumulative
// production cost blows the package timeout. MUST NEVER be used in
// production — it provides negligible KDF hardening.
var TestArgon2Params = Argon2Params{
	Time:    1,
	Memory:  8 * 1024,
	Threads: 1,
}

// Sentinel errors.
var (
	// ErrWrongPassword is returned by Unwrap when the supplied
	// password does not match the wrapped key. Indistinguishable from
	// ErrTampered on the wire to avoid an oracle.
	ErrWrongPassword = errors.New("vault/crypto: wrong password")

	// ErrTampered indicates the wrapped ciphertext failed AEAD
	// verification — bit-flip, truncation, or substitution.
	ErrTampered = errors.New("vault/crypto: wrapped key tampered or corrupted")

	// ErrBadFormat indicates the wrapped bytes don't parse as a known
	// version of the wrap format.
	ErrBadFormat = errors.New("vault/crypto: bad wrap format")

	// ErrBadKey is returned when the caller-supplied vault key is the
	// wrong size or otherwise invalid.
	ErrBadKey = errors.New("vault/crypto: invalid vault key")

	// ErrBadParams is returned when Argon2Params are out of policy
	// (e.g. zero iterations or memory). Defends against
	// attacker-supplied parameters that would skip the KDF.
	ErrBadParams = errors.New("vault/crypto: invalid argon2 params")
)

// NewVaultKey returns a freshly generated 32-byte vault key.
func NewVaultKey() ([]byte, error) {
	k := make([]byte, VaultKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("vault/crypto: rand: %w", err)
	}
	return k, nil
}

// Wrap encrypts vaultKey with a key derived from password via Argon2id.
// The output blob is self-describing: format version, params, salt,
// nonce, ciphertext+tag. Pass to Unwrap with the same password to
// recover the vault key.
//
// The password is NOT zeroed by this function; the caller controls its
// lifetime.
func Wrap(password []byte, vaultKey []byte, params Argon2Params) ([]byte, error) {
	if len(vaultKey) != VaultKeySize {
		return nil, ErrBadKey
	}
	if err := validateParams(params); err != nil {
		return nil, err
	}

	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("vault/crypto: rand salt: %w", err)
	}

	wrappingKey := argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, chacha20poly1305.KeySize)
	defer zero(wrappingKey)

	aead, err := chacha20poly1305.NewX(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("vault/crypto: aead init: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault/crypto: rand nonce: %w", err)
	}

	header := encodeHeader(params, salt, nonce)
	// Bind header to the ciphertext via AAD so any field tampering
	// (e.g. raising Memory after the fact) fails the MAC.
	out := make([]byte, len(header), len(header)+len(vaultKey)+aead.Overhead())
	copy(out, header)
	out = aead.Seal(out, nonce, vaultKey, header)
	return out, nil
}

// Unwrap recovers a vault key wrapped by Wrap. Returns ErrWrongPassword
// or ErrTampered on failure — both surfaced via errors.Is.
func Unwrap(password []byte, wrapped []byte) ([]byte, error) {
	params, salt, nonce, ciphertext, header, err := decodeWrapped(wrapped)
	if err != nil {
		return nil, err
	}

	wrappingKey := argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, chacha20poly1305.KeySize)
	defer zero(wrappingKey)

	aead, err := chacha20poly1305.NewX(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("vault/crypto: aead init: %w", err)
	}
	plain, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		// AEAD failure could be wrong password OR tampered bytes.
		// We can't distinguish without an oracle. Caller treats both
		// the same.
		return nil, ErrWrongPassword
	}
	if len(plain) != VaultKeySize {
		zero(plain)
		return nil, ErrBadFormat
	}
	return plain, nil
}

// Header layout (big-endian):
//
//	[0]      version uint8
//	[1..5)   time    uint32
//	[5..9)   memory  uint32
//	[9]      threads uint8
//	[10..14) saltLen uint32
//	[14..18) nonceLen uint32
//	[18..18+saltLen)              salt
//	[18+saltLen..18+saltLen+nonceLen) nonce
//
// SaltLen and NonceLen are stored explicitly so future format changes
// don't break old wraps.
const (
	wrapHeaderFixedLen = 18
)

func encodeHeader(params Argon2Params, salt, nonce []byte) []byte {
	hdr := make([]byte, wrapHeaderFixedLen+len(salt)+len(nonce))
	hdr[0] = WrapFormatVersion
	binary.BigEndian.PutUint32(hdr[1:5], params.Time)
	binary.BigEndian.PutUint32(hdr[5:9], params.Memory)
	hdr[9] = params.Threads
	binary.BigEndian.PutUint32(hdr[10:14], uint32(len(salt)))  //nolint:gosec // bounded by SaltSize
	binary.BigEndian.PutUint32(hdr[14:18], uint32(len(nonce))) //nolint:gosec // bounded by NonceSizeX
	copy(hdr[18:], salt)
	copy(hdr[18+len(salt):], nonce)
	return hdr
}

func decodeWrapped(wrapped []byte) (params Argon2Params, salt, nonce, ciphertext, header []byte, err error) {
	if len(wrapped) < wrapHeaderFixedLen {
		err = ErrBadFormat
		return
	}
	if wrapped[0] != WrapFormatVersion {
		err = ErrBadFormat
		return
	}
	params.Time = binary.BigEndian.Uint32(wrapped[1:5])
	params.Memory = binary.BigEndian.Uint32(wrapped[5:9])
	params.Threads = wrapped[9]
	saltLen := binary.BigEndian.Uint32(wrapped[10:14])
	nonceLen := binary.BigEndian.Uint32(wrapped[14:18])

	// Sanity bounds: a 1 GiB header is obviously malformed and would
	// cause us to allocate before we discover the truncation.
	const maxField = 1 << 20
	if saltLen > maxField || nonceLen > maxField {
		err = ErrBadFormat
		return
	}
	need := wrapHeaderFixedLen + int(saltLen) + int(nonceLen)
	if len(wrapped) < need {
		err = ErrBadFormat
		return
	}
	if err = validateParams(params); err != nil {
		return
	}
	salt = wrapped[wrapHeaderFixedLen : wrapHeaderFixedLen+int(saltLen)]
	nonce = wrapped[wrapHeaderFixedLen+int(saltLen) : need]
	ciphertext = wrapped[need:]
	header = wrapped[:need]
	if len(nonce) != chacha20poly1305.NonceSizeX {
		err = ErrBadFormat
		return
	}
	return
}

// Upper bounds defend against tampered on-disk params that would
// otherwise cause Argon2id to consume absurd time or RAM. Real users
// would never tune past these.
const (
	maxArgon2Time    = 16
	maxArgon2MemoryK = 1 << 20 // 1 GiB in KiB
	maxArgon2Threads = 16
)

func validateParams(p Argon2Params) error {
	// Lower bounds defend against an attacker swapping in trivial
	// params on disk. These are well below DefaultArgon2Params.
	if p.Time < 1 || p.Memory < 8*1024 || p.Threads < 1 {
		return ErrBadParams
	}
	if p.Time > maxArgon2Time || p.Memory > maxArgon2MemoryK || p.Threads > maxArgon2Threads {
		return ErrBadParams
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
