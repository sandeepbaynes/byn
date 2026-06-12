//go:build !linux && !darwin

package privsep

// ProvisionResult reports what provisioning did (idempotent re-runs).
type ProvisionResult struct{ AlreadyProvisioned bool }

// runner runs a privileged command (injected for tests).
type runner func(cmd string, args ...string) error

// HelperConfigPath returns ErrUnsupported on unsupported platforms.
func HelperConfigPath() string {
	return ""
}

// HelperDestPath returns empty string on unsupported platforms.
func HelperDestPath() string {
	return ""
}

// provisionUsers returns ErrUnsupported on unsupported platforms.
func provisionUsers(_ uidLookup, _ runner) (ProvisionResult, error) {
	return ProvisionResult{}, ErrUnsupported
}

// installHelper returns ErrUnsupported on unsupported platforms.
func installHelper(_ runner, _, _, _ string, _, _ int) error {
	return ErrUnsupported
}

// Setup returns ErrUnsupported on unsupported platforms.
func Setup(_ runner, _, _, _ string) error {
	return ErrUnsupported
}
