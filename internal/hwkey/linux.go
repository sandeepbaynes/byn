//go:build linux

package hwkey

// LinuxTPM2 is a TPM 2.0-backed Provider for Linux.
//
// Status: stub. The real implementation lives on the user's Linux dev
// box and will use github.com/google/go-tpm to seal/unseal blobs
// against a primary key under the storage hierarchy. This file exists
// so cross-platform code can reference the symbol without #ifdef
// gymnastics.
//
// All methods return ErrProviderUnavailable.
type LinuxTPM2 struct {
	handle string
}

// NewLinuxTPM2 returns a stub TPM2 provider with the given handle.
func NewLinuxTPM2(handle string) *LinuxTPM2 {
	return &LinuxTPM2{handle: handle}
}

// Name implements Provider.
func (l *LinuxTPM2) Name() string { return "linux-tpm2" }

// Available implements Provider. Always false in the stub; the real
// impl will check for /dev/tpm0 or /dev/tpmrm0.
func (l *LinuxTPM2) Available() bool { return false }

// CreateOrLoad implements Provider.
func (l *LinuxTPM2) CreateOrLoad() error { return ErrProviderUnavailable }

// Wrap implements Provider.
func (l *LinuxTPM2) Wrap(_ []byte) ([]byte, error) { return nil, ErrProviderUnavailable }

// Unwrap implements Provider.
func (l *LinuxTPM2) Unwrap(_ []byte) ([]byte, error) { return nil, ErrProviderUnavailable }

// Erase implements Provider.
func (l *LinuxTPM2) Erase() error { return ErrProviderUnavailable }
