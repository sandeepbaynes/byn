// Package hwkey defines a hardware-backed wrapping key provider.
//
// A Provider stores a single asymmetric or symmetric wrapping key whose
// private material lives in a hardware security element (Secure Enclave,
// TPM2) where available, or in a software fallback file. Callers Wrap a
// plaintext blob (e.g. the vault key) and later Unwrap it.
//
// Provider implementations are platform-specific and selected at build
// time via build tags. The Software provider works everywhere and is
// used in tests and as an opt-in fallback when no hardware element is
// available.
package hwkey

import "errors"

// Sentinel errors returned by Provider implementations.
//
// Callers should check via errors.Is rather than string-matching.
var (
	// ErrProviderUnavailable indicates the provider cannot be used on
	// this system (missing hardware, missing OS support, missing
	// entitlements, etc.). Callers may fall back to a different
	// provider.
	ErrProviderUnavailable = errors.New("hwkey: provider unavailable")

	// ErrKeyNotFound indicates Unwrap or Erase was called but no key
	// has been created for this handle.
	ErrKeyNotFound = errors.New("hwkey: key not found")

	// ErrKeyExists indicates CreateOrLoad found an existing key when
	// the caller's options required a fresh one. CreateOrLoad in its
	// default mode is idempotent and does not return this.
	ErrKeyExists = errors.New("hwkey: key already exists")

	// ErrUnwrap indicates a ciphertext could not be decrypted — wrong
	// key, tampered bytes, or wrong algorithm. The implementation must
	// not leak which.
	ErrUnwrap = errors.New("hwkey: unwrap failed")
)

// Provider provides hardware-backed wrapping for a single key handle.
//
// All methods are safe for concurrent use unless documented otherwise.
type Provider interface {
	// Name returns a stable identifier for the provider implementation
	// (e.g. "macos-secure-enclave", "linux-tpm2", "software"). Used
	// for diagnostics and audit logging.
	Name() string

	// Available reports whether the provider can be used on the
	// current system. Implementations may probe hardware on first
	// call; result is cached.
	Available() bool

	// CreateOrLoad ensures a wrapping key exists for this provider's
	// configured handle. Idempotent: calling twice is not an error.
	// Returns ErrProviderUnavailable if the underlying hardware is
	// missing.
	CreateOrLoad() error

	// Wrap encrypts plaintext using the wrapping key. Output format is
	// opaque to callers and may include algorithm identifiers,
	// nonces, ephemeral keys, etc. Returns ErrKeyNotFound if no key
	// has been created.
	Wrap(plaintext []byte) ([]byte, error)

	// Unwrap decrypts ciphertext produced by a previous Wrap call
	// with the same wrapping key. Returns ErrUnwrap if the ciphertext
	// is invalid, tampered, or was wrapped with a different key.
	Unwrap(ciphertext []byte) ([]byte, error)

	// Erase removes the wrapping key from hardware or storage.
	// Irreversible. Returns ErrKeyNotFound if no key exists. After
	// Erase succeeds, subsequent Wrap/Unwrap calls return
	// ErrKeyNotFound until a new CreateOrLoad.
	Erase() error
}
