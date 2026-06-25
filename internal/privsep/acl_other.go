//go:build !linux && !darwin

package privsep

// GrantProjectACL is a no-op on platforms with no supported ACL mechanism,
// keeping the daemon building. Privsep itself is unsupported here (Setup
// returns ErrUnsupported), so this is never reached with privsep enabled.
func GrantProjectACL(_ func(name string, args ...string) error, _, _ string) error {
	return nil
}

// RevokeProjectACL is a no-op on unsupported platforms. See GrantProjectACL.
func RevokeProjectACL(_ func(name string, args ...string) error, _, _ string) error {
	return nil
}

// GrantBynReadACL is a no-op on platforms with no supported ACL mechanism.
// See GrantProjectACL.
func GrantBynReadACL(_ func(name string, args ...string) error, _, _ string) error {
	return nil
}

// RevokeBynReadACL is a no-op on unsupported platforms. See GrantBynReadACL.
func RevokeBynReadACL(_ func(name string, args ...string) error, _, _ string) error {
	return nil
}

// GrantDaemonHomeAccess is a no-op on unsupported platforms.
func GrantDaemonHomeAccess(_ func(name string, args ...string) error, _ string) error { return nil }
