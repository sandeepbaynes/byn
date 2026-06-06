package hwkey

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// softwareKeyVersion is the on-disk format version. Bump on incompatible
// changes; never reuse a value.
const softwareKeyVersion byte = 1

// softwareKeyFileMode is the required mode for the key file. Anything
// more permissive is a security bug and Load will reject it.
const softwareKeyFileMode = 0o600

// Software is a file-backed Provider used as an opt-in fallback on
// platforms without a hardware security element, and as the default in
// tests.
//
// Security: the wrapping key sits on disk in a single file with mode
// 0600. An attacker with read access to the file can decrypt anything
// that was wrapped with it. This is strictly weaker than a hardware-
// backed provider and is only suitable for development or for users
// who have explicitly opted into the trade-off.
type Software struct {
	path string

	mu  sync.RWMutex
	key []byte // 32 bytes; nil until CreateOrLoad
}

// NewSoftware returns a Software provider that stores its wrapping key
// at path. The file is created on first CreateOrLoad; missing parent
// directories are created with mode 0700.
func NewSoftware(path string) *Software {
	return &Software{path: path}
}

// Name implements Provider.
func (s *Software) Name() string { return "software" }

// Available implements Provider. The software provider is always
// available — the whole point of the fallback.
func (s *Software) Available() bool { return true }

// CreateOrLoad implements Provider. Idempotent.
func (s *Software) CreateOrLoad() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.key != nil {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("hwkey/software: ensure dir: %w", err)
	}

	key, err := loadSoftwareKey(s.path)
	if err == nil {
		s.key = key
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Create.
	s.key = make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(s.key); err != nil {
		s.key = nil
		return fmt.Errorf("hwkey/software: rand: %w", err)
	}
	if err := writeSoftwareKey(s.path, s.key); err != nil {
		s.key = nil
		return err
	}
	return nil
}

// Wrap implements Provider.
func (s *Software) Wrap(plaintext []byte) ([]byte, error) {
	s.mu.RLock()
	key := s.key
	s.mu.RUnlock()
	if key == nil {
		return nil, ErrKeyNotFound
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("hwkey/software: aead init: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("hwkey/software: nonce: %w", err)
	}
	// Output layout: [version || nonce || ciphertext+tag].
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, softwareKeyVersion)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, nil)
	return out, nil
}

// Unwrap implements Provider.
func (s *Software) Unwrap(ciphertext []byte) ([]byte, error) {
	s.mu.RLock()
	key := s.key
	s.mu.RUnlock()
	if key == nil {
		return nil, ErrKeyNotFound
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("hwkey/software: aead init: %w", err)
	}
	nonceSize := aead.NonceSize()
	if len(ciphertext) < 1+nonceSize+aead.Overhead() {
		return nil, ErrUnwrap
	}
	if ciphertext[0] != softwareKeyVersion {
		return nil, ErrUnwrap
	}
	nonce := ciphertext[1 : 1+nonceSize]
	body := ciphertext[1+nonceSize:]
	plain, err := aead.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, ErrUnwrap
	}
	return plain, nil
}

// Erase implements Provider.
func (s *Software) Erase() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.Remove(s.path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.key = nil
			return ErrKeyNotFound
		}
		return fmt.Errorf("hwkey/software: remove key file: %w", err)
	}
	s.key = nil
	return nil
}

func loadSoftwareKey(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&^softwareKeyFileMode != 0 {
		return nil, fmt.Errorf("hwkey/software: %s has insecure mode %o (require %o)", path, info.Mode().Perm(), softwareKeyFileMode)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is provider-configured
	if err != nil {
		return nil, err
	}
	if len(data) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("hwkey/software: %s has wrong size %d", path, len(data))
	}
	return data, nil
}

func writeSoftwareKey(path string, key []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hwkey-software-*")
	if err != nil {
		return fmt.Errorf("hwkey/software: tempfile: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		// If the rename succeeded, removing the tmp path is a no-op
		// because the file no longer exists at that name; ignore the
		// error.
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(softwareKeyFileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("hwkey/software: chmod: %w", err)
	}
	if _, err := tmp.Write(key); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("hwkey/software: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("hwkey/software: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("hwkey/software: close: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("hwkey/software: rename: %w", err)
	}
	return nil
}
