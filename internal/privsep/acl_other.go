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
