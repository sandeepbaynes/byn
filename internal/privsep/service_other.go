//go:build !linux && !darwin

package privsep

// InstallService returns ErrUnsupported on platforms without a system service
// manager byn provisions (only linux/systemd and darwin/launchd are supported).
// The stub keeps callers (internal/setup, cmd/byn) compiling on every platform;
// `byn setup` itself already refuses to proceed on an unsupported OS via the
// other privsep primitives returning ErrUnsupported.
func InstallService(_ runner, _ string) error { return ErrUnsupported }

// UninstallService returns ErrUnsupported on unsupported platforms.
func UninstallService(_ runner) error { return ErrUnsupported }

// RestartService returns ErrUnsupported on platforms without a managed service.
func RestartService(_ runner) error { return ErrUnsupported }

// StopService returns ErrUnsupported on platforms without a managed service.
func StopService(_ runner) error { return ErrUnsupported }
